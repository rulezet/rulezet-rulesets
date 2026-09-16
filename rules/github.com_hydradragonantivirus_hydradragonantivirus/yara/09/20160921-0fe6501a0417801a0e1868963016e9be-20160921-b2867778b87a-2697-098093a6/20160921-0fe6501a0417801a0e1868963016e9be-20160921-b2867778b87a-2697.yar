rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_b2867778b87a_2697 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1 = "){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})()" ascii
    $s2 = "unction f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s3 = "return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})" ascii
    $s4 = "){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";}" ascii
    $s5 = "function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DNa\";})(),(function f000(){r" ascii
    $s6 = "x\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function " ascii
    $s7 = " \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}