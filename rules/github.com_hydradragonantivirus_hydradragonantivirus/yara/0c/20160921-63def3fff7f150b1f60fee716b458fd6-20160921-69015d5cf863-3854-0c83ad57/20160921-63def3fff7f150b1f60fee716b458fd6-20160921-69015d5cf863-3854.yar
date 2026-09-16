rule _20160921_63def3fff7f150b1f60fee716b458fd6_20160921_69015d5cf863_3854 {
  meta:
    description = "datamaliciousorder - from files 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000()" ascii
    $s2 = "MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(functi" ascii
    $s3 = "n f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "tion f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return " ascii
    $s5 = "n \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s6 = "){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}