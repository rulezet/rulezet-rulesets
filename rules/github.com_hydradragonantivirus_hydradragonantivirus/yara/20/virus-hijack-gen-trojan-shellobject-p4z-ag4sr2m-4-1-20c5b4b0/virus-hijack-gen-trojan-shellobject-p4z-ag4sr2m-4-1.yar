rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_4_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_4_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "68c20c6a5e67c70a346a1437115dfc8665f1db9694bede7b8a298d0747707649"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 60 60 ff 34 24 8d 64 24 44 0f 82 80 39 03 00 e9 }
      $op1 = { c1 65 e8 08 c1 65 e4 08 50 ac c0 c8 05 34 81 fe }
      $op2 = { e8 38 f0 ff ff 83 e9 01 0f 85 d9 ff ff ff c3 f5 }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}