rule TTP_XOR_QUAD_CurrentVersionRun_da45 {
  strings:
    $key_da45 = { 89 2a [2] ad 24 [2] 86 08 [2] a8 2a [2] bc 31 [2] b3 2b [2] ad 36 [2] af 37 [2] b4 31 [2] a8 36 [2] b4 19 }

  condition:
    any of them
}