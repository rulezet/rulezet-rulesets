rule TTP_XOR_QUAD_CurrentVersionRun_67a6 {
  strings:
    $key_67a6 = { 34 c9 [2] 10 c7 [2] 3b eb [2] 15 c9 [2] 01 d2 [2] 0e c8 [2] 10 d5 [2] 12 d4 [2] 09 d2 [2] 15 d5 [2] 09 fa }

  condition:
    any of them
}