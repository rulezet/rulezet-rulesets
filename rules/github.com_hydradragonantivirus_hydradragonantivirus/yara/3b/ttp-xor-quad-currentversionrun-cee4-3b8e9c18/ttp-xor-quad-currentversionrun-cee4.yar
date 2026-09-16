rule TTP_XOR_QUAD_CurrentVersionRun_cee4 {
  strings:
    $key_cee4 = { 9d 8b [2] b9 85 [2] 92 a9 [2] bc 8b [2] a8 90 [2] a7 8a [2] b9 97 [2] bb 96 [2] a0 90 [2] bc 97 [2] a0 b8 }

  condition:
    any of them
}