rule _20160921_11c4976357ef8a651d058575507518ca_20160921_203e0165d7eb_1659 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash3       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash4       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash5       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1  = "on fuck(){return \"Ik\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){r" ascii
    $s3  = "k(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s4  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s5  = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(fu" ascii
    $s6  = "{return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(" ascii
    $s7  = "Sf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s8  = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s9  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s10 = "(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s11 = "ck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}