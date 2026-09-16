rule TTP_XOR_QUAD_CurrentVersionRun_c3e4 {
  strings:
    $key_c3e4 = { 90 8b [2] b4 85 [2] 9f a9 [2] b1 8b [2] a5 90 [2] aa 8a [2] b4 97 [2] b6 96 [2] ad 90 [2] b1 97 [2] ad b8 }

  condition:
    any of them
}