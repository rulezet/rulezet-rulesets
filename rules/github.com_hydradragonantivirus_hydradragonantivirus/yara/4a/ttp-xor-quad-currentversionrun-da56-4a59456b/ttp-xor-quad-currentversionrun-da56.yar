rule TTP_XOR_QUAD_CurrentVersionRun_da56 {
  strings:
    $key_da56 = { 89 39 [2] ad 37 [2] 86 1b [2] a8 39 [2] bc 22 [2] b3 38 [2] ad 25 [2] af 24 [2] b4 22 [2] a8 25 [2] b4 0a }

  condition:
    any of them
}