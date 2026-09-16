rule TTP_XOR_QUAD_CurrentVersionRun_27a6 {
  strings:
    $key_27a6 = { 74 c9 [2] 50 c7 [2] 7b eb [2] 55 c9 [2] 41 d2 [2] 4e c8 [2] 50 d5 [2] 52 d4 [2] 49 d2 [2] 55 d5 [2] 49 fa }

  condition:
    any of them
}