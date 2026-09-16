rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_69015d5cf863_4524 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash4       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "urn \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "unction f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return " ascii
    $s4 = "\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s5 = "return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}