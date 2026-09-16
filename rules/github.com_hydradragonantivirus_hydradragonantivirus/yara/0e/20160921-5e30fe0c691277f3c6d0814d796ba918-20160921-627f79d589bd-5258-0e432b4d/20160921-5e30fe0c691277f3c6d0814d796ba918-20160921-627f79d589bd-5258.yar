rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_627f79d589bd_5258 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash4       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash5       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s2 = "{return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})" ascii
    $s3 = " \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s4 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}