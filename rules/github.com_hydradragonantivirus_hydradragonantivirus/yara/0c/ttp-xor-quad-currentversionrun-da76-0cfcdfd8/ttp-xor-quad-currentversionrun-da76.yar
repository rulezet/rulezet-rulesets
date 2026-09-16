rule TTP_XOR_QUAD_CurrentVersionRun_da76 {
  strings:
    $key_da76 = { 89 19 [2] ad 17 [2] 86 3b [2] a8 19 [2] bc 02 [2] b3 18 [2] ad 05 [2] af 04 [2] b4 02 [2] a8 05 [2] b4 2a }

  condition:
    any of them
}