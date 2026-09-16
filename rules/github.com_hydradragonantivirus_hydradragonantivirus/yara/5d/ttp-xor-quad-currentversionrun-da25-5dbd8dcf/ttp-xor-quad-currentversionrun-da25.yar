rule TTP_XOR_QUAD_CurrentVersionRun_da25 {
  strings:
    $key_da25 = { 89 4a [2] ad 44 [2] 86 68 [2] a8 4a [2] bc 51 [2] b3 4b [2] ad 56 [2] af 57 [2] b4 51 [2] a8 56 [2] b4 79 }

  condition:
    any of them
}