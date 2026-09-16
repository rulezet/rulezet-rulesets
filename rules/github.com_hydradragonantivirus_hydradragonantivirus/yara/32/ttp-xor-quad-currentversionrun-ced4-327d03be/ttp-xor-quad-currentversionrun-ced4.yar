rule TTP_XOR_QUAD_CurrentVersionRun_ced4 {
  strings:
    $key_ced4 = { 9d bb [2] b9 b5 [2] 92 99 [2] bc bb [2] a8 a0 [2] a7 ba [2] b9 a7 [2] bb a6 [2] a0 a0 [2] bc a7 [2] a0 88 }

  condition:
    any of them
}