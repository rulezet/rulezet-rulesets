rule TTP_XOR_QUAD_CurrentVersionRun_e5c6 {
  strings:
    $key_e5c6 = { b6 a9 [2] 92 a7 [2] b9 8b [2] 97 a9 [2] 83 b2 [2] 8c a8 [2] 92 b5 [2] 90 b4 [2] 8b b2 [2] 97 b5 [2] 8b 9a }

  condition:
    any of them
}