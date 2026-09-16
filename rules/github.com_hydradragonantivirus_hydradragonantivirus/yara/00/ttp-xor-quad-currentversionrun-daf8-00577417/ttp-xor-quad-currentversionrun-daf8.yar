rule TTP_XOR_QUAD_CurrentVersionRun_daf8 {
  strings:
    $key_daf8 = { 89 97 [2] ad 99 [2] 86 b5 [2] a8 97 [2] bc 8c [2] b3 96 [2] ad 8b [2] af 8a [2] b4 8c [2] a8 8b [2] b4 a4 }

  condition:
    any of them
}