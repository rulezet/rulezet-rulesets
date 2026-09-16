rule _20160921_c07f026b9458324f489ec08b7859e758_20160921_e53844f4bb18_4050 {
  meta:
    description = "datamaliciousorder - from files 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\"" ascii
    $s2 = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo0" ascii
    $s4 = "(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck()" ascii
    $s5 = "n \"UXf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s6 = " \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}