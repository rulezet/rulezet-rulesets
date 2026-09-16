rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_90c3374aed1b_3871 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){retur" ascii
    $s3 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(functi" ascii
    $s4 = "nction f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s5 = "ion f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"" ascii
    $s6 = "(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}