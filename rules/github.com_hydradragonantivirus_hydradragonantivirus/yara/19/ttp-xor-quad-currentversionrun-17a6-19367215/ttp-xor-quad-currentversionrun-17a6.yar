rule TTP_XOR_QUAD_CurrentVersionRun_17a6 {
  strings:
    $key_17a6 = { 44 c9 [2] 60 c7 [2] 4b eb [2] 65 c9 [2] 71 d2 [2] 7e c8 [2] 60 d5 [2] 62 d4 [2] 79 d2 [2] 65 d5 [2] 79 fa }

  condition:
    any of them
}