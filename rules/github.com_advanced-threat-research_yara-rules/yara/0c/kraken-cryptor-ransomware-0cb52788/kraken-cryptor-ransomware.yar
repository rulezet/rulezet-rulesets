rule kraken_cryptor_ransomware {
   
   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Kraken"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
      hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"

   strings:
     
      $s1 = "Kraken Cryptor" fullword ascii nocase
      $s2 = "support_email" fullword ascii
      $fw1 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $fw2 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw3 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw4 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $uac = "<!--<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />-->   " fullword ascii
  
   condition:

      uint16(0) == 0x5a4d and
      filesize < 600KB and
      all of ($fw*) or
      all of ($s*) or
      $uac
}