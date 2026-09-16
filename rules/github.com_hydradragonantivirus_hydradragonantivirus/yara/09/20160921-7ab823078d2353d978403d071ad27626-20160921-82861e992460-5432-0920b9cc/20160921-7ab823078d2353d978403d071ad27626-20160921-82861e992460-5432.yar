rule _20160921_7ab823078d2353d978403d071ad27626_20160921_82861e992460_5432 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash2       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash3       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii
    $s2 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function f" ascii
    $s3 = "on fuck(){return \"To\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"" ascii
    $s4 = "rn \"YAv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s5 = "turn \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}