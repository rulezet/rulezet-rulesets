rule _20160921_510713862e5c8c05841e5272407127f3_20160921_a160e4a38580_3771 {
  meta:
    description = "datamaliciousorder - from files 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash2       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "eturn \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(" ascii
    $s2 = "eturn \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})()" ascii
    $s3 = "c\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(functio" ascii
    $s5 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s6 = ")(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}