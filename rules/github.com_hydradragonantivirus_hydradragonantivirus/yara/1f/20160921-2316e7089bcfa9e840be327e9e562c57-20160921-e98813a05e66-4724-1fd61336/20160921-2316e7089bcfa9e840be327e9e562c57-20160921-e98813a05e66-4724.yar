rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_e98813a05e66_4724 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "n \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s2 = "(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s3 = "(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s4 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(" ascii
    $s5 = "(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}