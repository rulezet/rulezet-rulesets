rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_f9054cc04d83_5308 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = " f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RP" ascii
    $s2 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\"" ascii
    $s3 = "on f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s4 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s5 = "eturn \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}