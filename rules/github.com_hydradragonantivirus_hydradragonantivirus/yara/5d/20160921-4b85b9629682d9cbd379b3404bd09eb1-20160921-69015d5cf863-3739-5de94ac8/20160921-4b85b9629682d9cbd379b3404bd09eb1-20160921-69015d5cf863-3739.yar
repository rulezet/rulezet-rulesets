rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_69015d5cf863_3739 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "s\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s2 = "00(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";" ascii
    $s3 = "turn \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})()," ascii
    $s4 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"ZIi\";})" ascii
    $s5 = "tion f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return" ascii
    $s6 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}