rule TTP_XOR_QUAD_CurrentVersionRun_2bb6 {
  strings:
    $key_2bb6 = { 78 d9 [2] 5c d7 [2] 77 fb [2] 59 d9 [2] 4d c2 [2] 42 d8 [2] 5c c5 [2] 5e c4 [2] 45 c2 [2] 59 c5 [2] 45 ea }

  condition:
    any of them
}