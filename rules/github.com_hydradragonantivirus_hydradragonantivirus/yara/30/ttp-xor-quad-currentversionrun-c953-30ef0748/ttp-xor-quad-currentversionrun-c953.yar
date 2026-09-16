rule TTP_XOR_QUAD_CurrentVersionRun_c953 {
  strings:
    $key_c953 = { 9a 3c [2] be 32 [2] 95 1e [2] bb 3c [2] af 27 [2] a0 3d [2] be 20 [2] bc 21 [2] a7 27 [2] bb 20 [2] a7 0f }

  condition:
    any of them
}