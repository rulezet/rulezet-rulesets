rule TTP_XOR_QUAD_CurrentVersionRun_ceb3 {
  strings:
    $key_ceb3 = { 9d dc [2] b9 d2 [2] 92 fe [2] bc dc [2] a8 c7 [2] a7 dd [2] b9 c0 [2] bb c1 [2] a0 c7 [2] bc c0 [2] a0 ef }

  condition:
    any of them
}