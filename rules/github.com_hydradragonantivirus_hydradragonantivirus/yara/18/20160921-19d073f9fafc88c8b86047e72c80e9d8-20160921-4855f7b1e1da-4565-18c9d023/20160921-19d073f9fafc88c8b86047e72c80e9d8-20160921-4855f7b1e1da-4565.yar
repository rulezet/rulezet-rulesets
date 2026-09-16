rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_4855f7b1e1da_4565 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash3       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash4       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f0" ascii
    $s2 = "eturn \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s3 = "ction f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"" ascii
    $s5 = "Gn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}