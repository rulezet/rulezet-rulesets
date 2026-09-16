rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb0c589f9c88688bc47881ab95b7f51d8c2a9677ed93c3b4e0c254b2c1edbe35"

  strings:
    $s1  = "Use -n to set the N for the BSGS process. Bigger N more RAM needed" fullword ascii
    $s2  = "[E] -n param doesn't have exact square root" fullword ascii
    $s3  = "[E] thread thread_process" fullword ascii
    $s4  = "[+] Thread Key found privkey %s  " fullword ascii
    $s5  = "[+] Version %s, developed by AlbertoBSD" fullword ascii
    $s6  = "[+] -- from : 0x%s" fullword ascii
    $s7  = "Search for vanity Address, only with -m address" fullword ascii
    $s8  = "File with vanity Address to search, only with -m address" fullword ascii
    $s9  = " Hit!!!! Private Key: %s" fullword ascii
    $s10 = "Search for specific crypo. < btc, eth, all > valid only w/ -m address " fullword ascii
    $s11 = "[E] error hexs2bin" fullword ascii
    $s12 = "[+] Reading bP Table from file %s ." fullword ascii
    $s13 = "[+] Total %s keys in %s seconds: %s keys/s" fullword ascii
    $s14 = "[+] Thread %s  " fullword ascii
    $s15 = "[+] Reading bloom filter from file %s " fullword ascii
    $s16 = " ->version = %d.%d" fullword ascii
    $s17 = "[+] File mark already sorted, skipping sort proccess" fullword ascii
    $s18 = "[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)" fullword ascii
    $s19 = "[E] Invalid Minikey length %i : %s" fullword ascii
    $s20 = "[E] Error reading the file %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}