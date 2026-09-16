rule TTP_XOR_QUAD_CurrentVersionRun_d283 {
  strings:
    $key_d283 = { 81 ec [2] a5 e2 [2] 8e ce [2] a0 ec [2] b4 f7 [2] bb ed [2] a5 f0 [2] a7 f1 [2] bc f7 [2] a0 f0 [2] bc df }

  condition:
    any of them
}