rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_d4b576a05afd_3092 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"

  strings:
    $s1 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"X" ascii
    $s2 = "ck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\"" ascii
    $s3 = "urn \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s4 = "fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\"" ascii
    $s5 = ",(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){" ascii
    $s6 = "unction fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s7 = "on fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}