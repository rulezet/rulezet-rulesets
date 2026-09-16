rule TTP_XOR_QUAD_CurrentVersionRun_4eb6 {
  strings:
    $key_4eb6 = { 1d d9 [2] 39 d7 [2] 12 fb [2] 3c d9 [2] 28 c2 [2] 27 d8 [2] 39 c5 [2] 3b c4 [2] 20 c2 [2] 3c c5 [2] 20 ea }

  condition:
    any of them
}