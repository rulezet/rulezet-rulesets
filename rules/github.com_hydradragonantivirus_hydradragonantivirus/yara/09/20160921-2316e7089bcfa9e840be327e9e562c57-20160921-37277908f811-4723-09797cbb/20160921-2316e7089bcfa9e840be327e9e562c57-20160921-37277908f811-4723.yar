rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_37277908f811_4723 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "n f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s2 = "})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s3 = "ion f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "ion f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = "\"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}