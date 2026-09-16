rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_f9054cc04d83_1487 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1  = "n \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s2  = "Mz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function " ascii
    $s3  = ",(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s4  = "\"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s5  = "return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s6  = "(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii
    $s7  = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){" ascii
    $s8  = "function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){ret" ascii
    $s9  = "eturn \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})()" ascii
    $s10 = "t\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii
    $s11 = "tion f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s12 = "\"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s13 = "rn \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}