rule TTP_XOR_QUAD_CurrentVersionRun_da53 {
  strings:
    $key_da53 = { 89 3c [2] ad 32 [2] 86 1e [2] a8 3c [2] bc 27 [2] b3 3d [2] ad 20 [2] af 21 [2] b4 27 [2] a8 20 [2] b4 0f }

  condition:
    any of them
}