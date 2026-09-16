rule TTP_XOR_QUAD_CurrentVersionRun_d7e4 {
  strings:
    $key_d7e4 = { 84 8b [2] a0 85 [2] 8b a9 [2] a5 8b [2] b1 90 [2] be 8a [2] a0 97 [2] a2 96 [2] b9 90 [2] a5 97 [2] b9 b8 }

  condition:
    any of them
}