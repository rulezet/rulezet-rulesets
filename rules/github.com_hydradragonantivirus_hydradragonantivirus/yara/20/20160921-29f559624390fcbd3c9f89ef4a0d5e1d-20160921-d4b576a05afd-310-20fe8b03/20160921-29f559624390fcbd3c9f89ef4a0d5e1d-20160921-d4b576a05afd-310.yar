rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_d4b576a05afd_310 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"
    hash3       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1  = "tion fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2  = "urn \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s3  = "){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm" ascii
    $s5  = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\"" ascii
    $s6  = "on fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s7  = "(){return \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";" ascii
    $s8  = "turn \"Bz\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s9  = "n fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s10 = "turn \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s11 = "fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s12 = "Go\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s13 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){retu" ascii
    $s14 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function " ascii
    $s15 = "return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(" ascii
    $s16 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s17 = " \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s18 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s19 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s20 = "PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}