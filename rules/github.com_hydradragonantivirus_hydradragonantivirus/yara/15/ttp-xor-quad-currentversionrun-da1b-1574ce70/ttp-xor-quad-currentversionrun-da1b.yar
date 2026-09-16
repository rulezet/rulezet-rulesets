rule TTP_XOR_QUAD_CurrentVersionRun_da1b {
  strings:
    $key_da1b = { 89 74 [2] ad 7a [2] 86 56 [2] a8 74 [2] bc 6f [2] b3 75 [2] ad 68 [2] af 69 [2] b4 6f [2] a8 68 [2] b4 47 }

  condition:
    any of them
}