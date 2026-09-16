rule _20160921_802181e3d75c3e2d045cebba97849683_20160922_9d6af2734812_5456 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "turn \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})()," ascii
    $s2 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(" ascii
    $s3 = "00(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\"" ascii
    $s4 = "x\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5 = "){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}