rule _20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1_20160921_d7492227e681_4010 {
  meta:
    description = "datamaliciousorder - from files 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1 = ",(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s2 = "\"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(functi" ascii
    $s3 = "n f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"O" ascii
    $s4 = "00(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s5 = "){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";}" ascii
    $s6 = "})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}