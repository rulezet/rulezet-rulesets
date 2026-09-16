rule TTP_XOR_QUAD_CurrentVersionRun_da36 {
  strings:
    $key_da36 = { 89 59 [2] ad 57 [2] 86 7b [2] a8 59 [2] bc 42 [2] b3 58 [2] ad 45 [2] af 44 [2] b4 42 [2] a8 45 [2] b4 6a }

  condition:
    any of them
}