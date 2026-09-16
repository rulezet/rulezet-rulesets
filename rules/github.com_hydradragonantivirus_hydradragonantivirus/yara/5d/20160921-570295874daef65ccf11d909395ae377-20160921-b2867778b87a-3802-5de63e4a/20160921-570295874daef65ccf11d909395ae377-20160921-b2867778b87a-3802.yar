rule _20160921_570295874daef65ccf11d909395ae377_20160921_b2867778b87a_3802 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "on f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s2 = "(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(" ascii
    $s3 = "turn \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";" ascii
    $s5 = "})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s6 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}