rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_f9054cc04d83_3285 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = ";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii
    $s2 = "unction f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f000(){ret" ascii
    $s3 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\"" ascii
    $s4 = "(){return \"Br\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})" ascii
    $s5 = "function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s6 = "{return \"Go\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}