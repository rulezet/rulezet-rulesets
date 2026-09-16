rule TTP_XOR_QUAD_CurrentVersionRun_c3f8 {
  strings:
    $key_c3f8 = { 90 97 [2] b4 99 [2] 9f b5 [2] b1 97 [2] a5 8c [2] aa 96 [2] b4 8b [2] b6 8a [2] ad 8c [2] b1 8b [2] ad a4 }

  condition:
    any of them
}