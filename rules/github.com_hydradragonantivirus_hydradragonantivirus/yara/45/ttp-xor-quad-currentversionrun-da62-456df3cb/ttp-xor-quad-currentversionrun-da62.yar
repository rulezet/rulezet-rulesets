rule TTP_XOR_QUAD_CurrentVersionRun_da62 {
  strings:
    $key_da62 = { 89 0d [2] ad 03 [2] 86 2f [2] a8 0d [2] bc 16 [2] b3 0c [2] ad 11 [2] af 10 [2] b4 16 [2] a8 11 [2] b4 3e }

  condition:
    any of them
}