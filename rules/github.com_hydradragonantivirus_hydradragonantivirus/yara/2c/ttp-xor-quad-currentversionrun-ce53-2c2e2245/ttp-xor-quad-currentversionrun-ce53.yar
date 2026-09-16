rule TTP_XOR_QUAD_CurrentVersionRun_ce53 {
  strings:
    $key_ce53 = { 9d 3c [2] b9 32 [2] 92 1e [2] bc 3c [2] a8 27 [2] a7 3d [2] b9 20 [2] bb 21 [2] a0 27 [2] bc 20 [2] a0 0f }

  condition:
    any of them
}