rule TTP_XOR_QUAD_CurrentVersionRun_da78 {
  strings:
    $key_da78 = { 89 17 [2] ad 19 [2] 86 35 [2] a8 17 [2] bc 0c [2] b3 16 [2] ad 0b [2] af 0a [2] b4 0c [2] a8 0b [2] b4 24 }

  condition:
    any of them
}