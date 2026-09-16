rule miner_s_m_1 {
  meta:
    description = "miner-exe - from files s, m"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
    hash2       = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"

  strings:
    $s1  = "hash > target (false positive)" fullword ascii
    $s2  = "rpc2_login_decode" fullword ascii
    $s3  = "hash <= target" fullword ascii
    $s4  = "Skein1024_Process_Block" fullword ascii
    $s5  = "Skein_512_Process_Block" fullword ascii
    $s6  = "Skein_256_Process_Block" fullword ascii
    $s7  = "[X]^WTQRC@EFOLIJkhmngdabspuv" fullword ascii  
    $s8  = "|yz;8=>7412# %&/,)*" fullword ascii  
    $s9  = "dump_to_strbuffer" fullword ascii
    $s10 = "rpc2_login_lock" fullword ascii
    $s11 = "rpc2_login" fullword ascii
    $s12 = "num_processors" fullword ascii
    $s13 = "Target: %s" fullword ascii
    $s14 = "json_dump_file" fullword ascii
    $s15 = "dump_string" fullword ascii
    $s16 = "|ungXQJC4=&/" fullword ascii  
    $s17 = "rpc2_target" fullword ascii
    $s18 = "AO]Sywek1?-#" fullword ascii  
    $s19 = "dump_to_file" fullword ascii
    $s20 = "diff_to_target" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 700KB and (8 of them)
    ) or (all of them)
}