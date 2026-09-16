rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_66566a9bbc78_1486 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_66566a9bbc7830091a244fa6674b709b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"

  strings:
    $s1  = "})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000" ascii
    $s2  = "turn \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s3  = "f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJ" ascii
    $s4  = "function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s5  = "\"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(functi" ascii
    $s6  = "ion f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return " ascii
    $s7  = "urn \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s8  = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s9  = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(functio" ascii
    $s10 = "ction f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s11 = "){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(" ascii
    $s12 = "),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){" ascii
    $s13 = "nction f000(){return \"Tb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}