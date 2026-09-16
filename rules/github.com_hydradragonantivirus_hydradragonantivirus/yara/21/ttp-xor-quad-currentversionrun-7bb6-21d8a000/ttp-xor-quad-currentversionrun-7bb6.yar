rule TTP_XOR_QUAD_CurrentVersionRun_7bb6 {
  strings:
    $key_7bb6 = { 28 d9 [2] 0c d7 [2] 27 fb [2] 09 d9 [2] 1d c2 [2] 12 d8 [2] 0c c5 [2] 0e c4 [2] 15 c2 [2] 09 c5 [2] 15 ea }

  condition:
    any of them
}