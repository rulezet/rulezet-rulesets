rule TTP_XOR_QUAD_CurrentVersionRun_c4c6 {
  strings:
    $key_c4c6 = { 97 a9 [2] b3 a7 [2] 98 8b [2] b6 a9 [2] a2 b2 [2] ad a8 [2] b3 b5 [2] b1 b4 [2] aa b2 [2] b6 b5 [2] aa 9a }

  condition:
    any of them
}