rule TTP_XOR_QUAD_CurrentVersionRun_e5c7 {
  strings:
    $key_e5c7 = { b6 a8 [2] 92 a6 [2] b9 8a [2] 97 a8 [2] 83 b3 [2] 8c a9 [2] 92 b4 [2] 90 b5 [2] 8b b3 [2] 97 b4 [2] 8b 9b }

  condition:
    any of them
}