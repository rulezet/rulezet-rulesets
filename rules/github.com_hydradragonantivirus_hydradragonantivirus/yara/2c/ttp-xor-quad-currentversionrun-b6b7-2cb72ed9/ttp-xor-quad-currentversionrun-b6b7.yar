rule TTP_XOR_QUAD_CurrentVersionRun_b6b7 {
  strings:
    $key_b6b7 = { e5 d8 [2] c1 d6 [2] ea fa [2] c4 d8 [2] d0 c3 [2] df d9 [2] c1 c4 [2] c3 c5 [2] d8 c3 [2] c4 c4 [2] d8 eb }

  condition:
    any of them
}