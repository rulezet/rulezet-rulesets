rule kraken_cryptor_ransomware_loader {

   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware loader"
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

      $pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
      $s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
      $s3 = "public_key" fullword ascii
      $s4 = "KRAKEN DECRYPTOR" ascii
      $s5 = "UNIQUE KEY" fullword ascii

   condition:

       uint16(0) == 0x5a4d and 
       filesize < 600KB  and 
       $pdb or 
       all of ($s*)
}