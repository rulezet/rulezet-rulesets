rule TTP_XOR_QUAD_CurrentVersionRun_8eb7 {
  strings:
    $key_8eb7 = { dd d8 [2] f9 d6 [2] d2 fa [2] fc d8 [2] e8 c3 [2] e7 d9 [2] f9 c4 [2] fb c5 [2] e0 c3 [2] fc c4 [2] e0 eb }

  condition:
    any of them
}