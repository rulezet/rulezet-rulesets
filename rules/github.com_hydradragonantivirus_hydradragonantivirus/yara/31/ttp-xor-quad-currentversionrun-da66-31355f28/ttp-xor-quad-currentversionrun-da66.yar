rule TTP_XOR_QUAD_CurrentVersionRun_da66 {
  strings:
    $key_da66 = { 89 09 [2] ad 07 [2] 86 2b [2] a8 09 [2] bc 12 [2] b3 08 [2] ad 15 [2] af 14 [2] b4 12 [2] a8 15 [2] b4 3a }

  condition:
    any of them
}