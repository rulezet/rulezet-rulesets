rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_99d82d332144_3882 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(func" ascii
    $s2 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){r" ascii
    $s3 = " f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GG" ascii
    $s4 = "\"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(func" ascii
    $s5 = "rn \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s6 = "(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}