rule TTP_XOR_QUAD_CurrentVersionRun_d584 {
  strings:
    $key_d584 = { 86 eb [2] a2 e5 [2] 89 c9 [2] a7 eb [2] b3 f0 [2] bc ea [2] a2 f7 [2] a0 f6 [2] bb f0 [2] a7 f7 [2] bb d8 }

  condition:
    any of them
}