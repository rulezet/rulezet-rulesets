rule TTP_XOR_QUAD_CurrentVersionRun_41b6 {
  strings:
    $key_41b6 = { 12 d9 [2] 36 d7 [2] 1d fb [2] 33 d9 [2] 27 c2 [2] 28 d8 [2] 36 c5 [2] 34 c4 [2] 2f c2 [2] 33 c5 [2] 2f ea }

  condition:
    any of them
}