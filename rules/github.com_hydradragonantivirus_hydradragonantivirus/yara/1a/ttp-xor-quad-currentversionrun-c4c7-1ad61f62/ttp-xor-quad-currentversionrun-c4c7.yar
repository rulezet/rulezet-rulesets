rule TTP_XOR_QUAD_CurrentVersionRun_c4c7 {
  strings:
    $key_c4c7 = { 97 a8 [2] b3 a6 [2] 98 8a [2] b6 a8 [2] a2 b3 [2] ad a9 [2] b3 b4 [2] b1 b5 [2] aa b3 [2] b6 b4 [2] aa 9b }

  condition:
    any of them
}