rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_e1835bc92c46_5016 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(" ascii
    $s2 = "f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MM" ascii
    $s3 = "ion f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = " \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}