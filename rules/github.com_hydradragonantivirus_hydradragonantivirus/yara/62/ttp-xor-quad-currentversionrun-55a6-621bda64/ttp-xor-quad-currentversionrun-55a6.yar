rule TTP_XOR_QUAD_CurrentVersionRun_55a6 {
  strings:
    $key_55a6 = { 06 c9 [2] 22 c7 [2] 09 eb [2] 27 c9 [2] 33 d2 [2] 3c c8 [2] 22 d5 [2] 20 d4 [2] 3b d2 [2] 27 d5 [2] 3b fa }

  condition:
    any of them
}