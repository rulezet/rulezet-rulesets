rule TTP_XOR_QUAD_CurrentVersionRun_0db7 {
  strings:
    $key_0db7 = { 5e d8 [2] 7a d6 [2] 51 fa [2] 7f d8 [2] 6b c3 [2] 64 d9 [2] 7a c4 [2] 78 c5 [2] 63 c3 [2] 7f c4 [2] 63 eb }

  condition:
    any of them
}