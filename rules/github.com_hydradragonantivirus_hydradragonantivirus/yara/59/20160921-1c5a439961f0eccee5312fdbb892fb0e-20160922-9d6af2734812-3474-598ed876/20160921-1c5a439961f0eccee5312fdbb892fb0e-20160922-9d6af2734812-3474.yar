rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160922_9d6af2734812_3474 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "tion f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s2 = "{return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})" ascii
    $s3 = "function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s4 = "TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(functi" ascii
    $s5 = "eturn \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6 = "eturn \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}