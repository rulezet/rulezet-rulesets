rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_cae1392fd0c6_4989 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s2 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3 = "return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})()" ascii
    $s4 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s5 = "function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}