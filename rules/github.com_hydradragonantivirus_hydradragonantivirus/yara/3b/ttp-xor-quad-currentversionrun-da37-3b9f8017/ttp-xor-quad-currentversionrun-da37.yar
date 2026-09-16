rule TTP_XOR_QUAD_CurrentVersionRun_da37 {
  strings:
    $key_da37 = { 89 58 [2] ad 56 [2] 86 7a [2] a8 58 [2] bc 43 [2] b3 59 [2] ad 44 [2] af 45 [2] b4 43 [2] a8 44 [2] b4 6b }

  condition:
    any of them
}