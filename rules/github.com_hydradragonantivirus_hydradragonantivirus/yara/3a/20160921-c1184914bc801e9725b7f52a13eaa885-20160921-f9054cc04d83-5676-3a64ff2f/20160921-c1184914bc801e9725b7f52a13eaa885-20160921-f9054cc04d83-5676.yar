rule _20160921_c1184914bc801e9725b7f52a13eaa885_20160921_f9054cc04d83_5676 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s3 = "function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s4 = " \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s5 = "f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}