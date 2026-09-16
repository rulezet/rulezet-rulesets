rule _20160921_5eea6af1c50b807f547cb710eb413110_20160922_0d54e6d044b3_5275 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"

  strings:
    $s1 = "on f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s2 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh" ascii
    $s3 = "Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "n \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(f" ascii
    $s5 = "urn \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}