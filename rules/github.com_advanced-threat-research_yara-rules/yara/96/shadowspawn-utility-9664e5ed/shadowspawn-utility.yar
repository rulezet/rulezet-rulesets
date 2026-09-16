import "pe"
rule shadowspawn_utility {

   meta:

      description = "Rule to detect ShadowSpawn utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "utility"
      malware_family = "Trojan:W32/ShadowSpawn"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      

   strings:

      $pdb = "C:\\data\\projects\\shadowspawn\\src\\bin\\Release-W2K3\\x64\\ShadowSpawn.pdb" fullword ascii

      $op0 = { e9 34 ea ff ff cc cc cc cc 48 8d 8a 20 }
      $op1 = { 48 8b 85 e0 06 00 00 48 8d 34 00 48 8d 46 02 48 }
      $op2 = { e9 34 c1 ff ff cc cc cc cc 48 8b 8a 68 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( pe.imphash() == "eaae87b11d2ebdd286af419682037b4c" and
      all of them)
}