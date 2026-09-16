rule _20160921_bd6b4f506f527835a48516850a16c1a6_20160921_be4748da0160_5665 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){ret" ascii
    $s2 = " \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"YAv\";" ascii
    $s4 = "urn \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s5 = ")(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}