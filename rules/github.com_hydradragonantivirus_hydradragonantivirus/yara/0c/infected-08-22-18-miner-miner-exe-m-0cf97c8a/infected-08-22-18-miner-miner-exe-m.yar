rule infected_08_22_18_miner_miner_exe_m {
  meta:
    description = "miner-exe - file m"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"

  strings:
    $x1  = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
    $s2  = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
    $s3  = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
    $s4  = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s5  = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii
    $s6  = "pthread_mutex_destroy@@GLIBC_2.2.5" fullword ascii
    $s7  = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
    $s8  = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii
    $s9  = "pthread_mutex_init@@GLIBC_2.2.5" fullword ascii
    $s10 = "hash > target (false positive)" fullword ascii
    $s11 = "User-Agent: cpuminer/2.3.3" fullword ascii
    $s12 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
    $s13 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
    $s14 = "rpc2_login_decode" fullword ascii
    $s15 = "getwork failed, retry after %d seconds" fullword ascii
    $s16 = "Failed to call rpc command after %i tries" fullword ascii
    $s17 = "Failed to get Stratum session id" fullword ascii
    $s18 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
    $s19 = "hash <= target" fullword ascii
    $s20 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 500KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}