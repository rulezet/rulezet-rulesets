import "pe"
rule trochilus_softcell {

   meta:

      description = "Rule to detect Trochilus malware used in the SoftCell operation"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "trojan"
      malware_family = "Trojan:W32/Trochilus"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Shell.dll" fullword ascii
      $s2 = "photo.dat" fullword wide
      $s3 = "VW9HxtV9H|tQ9" fullword ascii
      $s4 = "G6uEGRich7uEG" fullword ascii

      $op0 = { e8 9d ad ff ff ff b6 a8 }
      $op1 = { e8 d4 ad ff ff ff b6 94 }
      $op2 = { e8 ea ad ff ff ff b6 8c }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( pe.imphash() == "8e13ebc144667958722686cb04ee16f8" and
      ( pe.exports("Entry") and
      pe.exports("Main") ) and
      all of them )
}