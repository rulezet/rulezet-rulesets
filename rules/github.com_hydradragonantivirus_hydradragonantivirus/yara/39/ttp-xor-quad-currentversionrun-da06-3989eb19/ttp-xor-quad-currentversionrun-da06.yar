rule TTP_XOR_QUAD_CurrentVersionRun_da06 {
  strings:
    $key_da06 = { 89 69 [2] ad 67 [2] 86 4b [2] a8 69 [2] bc 72 [2] b3 68 [2] ad 75 [2] af 74 [2] b4 72 [2] a8 75 [2] b4 5a }

  condition:
    any of them
}