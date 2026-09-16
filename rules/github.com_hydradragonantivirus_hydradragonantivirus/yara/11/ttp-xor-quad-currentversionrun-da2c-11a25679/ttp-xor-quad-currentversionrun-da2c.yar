rule TTP_XOR_QUAD_CurrentVersionRun_da2c {
  strings:
    $key_da2c = { 89 43 [2] ad 4d [2] 86 61 [2] a8 43 [2] bc 58 [2] b3 42 [2] ad 5f [2] af 5e [2] b4 58 [2] a8 5f [2] b4 70 }

  condition:
    any of them
}