rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_3e5e21af311d_1785 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1  = "ion f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s2  = "function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii
    $s3  = "eturn \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s4  = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"M" ascii
    $s5  = "(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\"" ascii
    $s6  = "BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s7  = " \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(fu" ascii
    $s8  = "return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})()," ascii
    $s9  = "rn \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s10 = "eturn \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}