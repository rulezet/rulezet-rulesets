rule TTP_XOR_QUAD_CurrentVersionRun_c3e5 {
  strings:
    $key_c3e5 = { 90 8a [2] b4 84 [2] 9f a8 [2] b1 8a [2] a5 91 [2] aa 8b [2] b4 96 [2] b6 97 [2] ad 91 [2] b1 96 [2] ad b9 }

  condition:
    any of them
}