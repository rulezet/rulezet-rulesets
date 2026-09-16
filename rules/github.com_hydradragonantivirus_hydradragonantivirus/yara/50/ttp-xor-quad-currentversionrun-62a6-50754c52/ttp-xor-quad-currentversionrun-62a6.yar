rule TTP_XOR_QUAD_CurrentVersionRun_62a6 {
  strings:
    $key_62a6 = { 31 c9 [2] 15 c7 [2] 3e eb [2] 10 c9 [2] 04 d2 [2] 0b c8 [2] 15 d5 [2] 17 d4 [2] 0c d2 [2] 10 d5 [2] 0c fa }

  condition:
    any of them
}