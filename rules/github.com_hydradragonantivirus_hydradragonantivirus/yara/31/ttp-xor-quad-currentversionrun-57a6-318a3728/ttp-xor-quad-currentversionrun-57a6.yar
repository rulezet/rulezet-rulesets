rule TTP_XOR_QUAD_CurrentVersionRun_57a6 {
  strings:
    $key_57a6 = { 04 c9 [2] 20 c7 [2] 0b eb [2] 25 c9 [2] 31 d2 [2] 3e c8 [2] 20 d5 [2] 22 d4 [2] 39 d2 [2] 25 d5 [2] 39 fa }

  condition:
    any of them
}