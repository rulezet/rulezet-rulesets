rule TTP_XOR_QUAD_CurrentVersionRun_c4d6 {
  strings:
    $key_c4d6 = { 97 b9 [2] b3 b7 [2] 98 9b [2] b6 b9 [2] a2 a2 [2] ad b8 [2] b3 a5 [2] b1 a4 [2] aa a2 [2] b6 a5 [2] aa 8a }

  condition:
    any of them
}