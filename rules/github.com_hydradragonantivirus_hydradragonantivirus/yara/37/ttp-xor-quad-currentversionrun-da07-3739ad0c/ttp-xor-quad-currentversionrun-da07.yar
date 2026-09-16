rule TTP_XOR_QUAD_CurrentVersionRun_da07 {
  strings:
    $key_da07 = { 89 68 [2] ad 66 [2] 86 4a [2] a8 68 [2] bc 73 [2] b3 69 [2] ad 74 [2] af 75 [2] b4 73 [2] a8 74 [2] b4 5b }

  condition:
    any of them
}