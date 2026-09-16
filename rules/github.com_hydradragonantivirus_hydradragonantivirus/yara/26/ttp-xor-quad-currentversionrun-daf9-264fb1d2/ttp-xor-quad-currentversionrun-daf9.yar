rule TTP_XOR_QUAD_CurrentVersionRun_daf9 {
  strings:
    $key_daf9 = { 89 96 [2] ad 98 [2] 86 b4 [2] a8 96 [2] bc 8d [2] b3 97 [2] ad 8a [2] af 8b [2] b4 8d [2] a8 8a [2] b4 a5 }

  condition:
    any of them
}