rule TTP_XOR_QUAD_CurrentVersionRun_21b6 {
  strings:
    $key_21b6 = { 72 d9 [2] 56 d7 [2] 7d fb [2] 53 d9 [2] 47 c2 [2] 48 d8 [2] 56 c5 [2] 54 c4 [2] 4f c2 [2] 53 c5 [2] 4f ea }

  condition:
    any of them
}