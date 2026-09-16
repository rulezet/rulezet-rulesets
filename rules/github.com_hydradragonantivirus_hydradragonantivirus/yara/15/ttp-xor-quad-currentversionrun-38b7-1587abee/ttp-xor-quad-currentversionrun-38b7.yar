rule TTP_XOR_QUAD_CurrentVersionRun_38b7 {
  strings:
    $key_38b7 = { 6b d8 [2] 4f d6 [2] 64 fa [2] 4a d8 [2] 5e c3 [2] 51 d9 [2] 4f c4 [2] 4d c5 [2] 56 c3 [2] 4a c4 [2] 56 eb }

  condition:
    any of them
}