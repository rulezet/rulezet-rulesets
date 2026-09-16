rule TTP_XOR_QUAD_CurrentVersionRun_da39 {
  strings:
    $key_da39 = { 89 56 [2] ad 58 [2] 86 74 [2] a8 56 [2] bc 4d [2] b3 57 [2] ad 4a [2] af 4b [2] b4 4d [2] a8 4a [2] b4 65 }

  condition:
    any of them
}