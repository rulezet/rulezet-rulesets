rule TTP_XOR_QUAD_CurrentVersionRun_da33 {
  strings:
    $key_da33 = { 89 5c [2] ad 52 [2] 86 7e [2] a8 5c [2] bc 47 [2] b3 5d [2] ad 40 [2] af 41 [2] b4 47 [2] a8 40 [2] b4 6f }

  condition:
    any of them
}