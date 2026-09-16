rule infected_08_22_18_miner_miner_exe_s {
  meta:
    description = "miner-exe - file s"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"

  strings:
    $x1  = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
    $s2  = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
    $s3  = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
    $s4  = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s5  = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
    $s6  = "hash > target (false positive)" fullword ascii
    $s7  = "User-Agent: cpuminer/2.3.3" fullword ascii
    $s8  = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
    $s9  = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
    $s10 = "rpc2_login_decode" fullword ascii
    $s11 = "getwork failed, retry after %d seconds" fullword ascii
    $s12 = "Failed to call rpc command after %i tries" fullword ascii
    $s13 = "Failed to get Stratum session id" fullword ascii
    $s14 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
    $s15 = "hash <= target" fullword ascii
    $s16 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
    $s17 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
    $s18 = "-S, --syslog          use system log for output messages" fullword ascii
    $s19 = "%s: unsupported non-option argument '%s'" fullword ascii
    $s20 = "Skein1024_Process_Block" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 700KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}