rule TTP_XOR_QUAD_CurrentVersionRun_3136 {
  strings:
    $key_3136 = { 62 59 [2] 46 57 [2] 6d 7b [2] 43 59 [2] 57 42 [2] 58 58 [2] 46 45 [2] 44 44 [2] 5f 42 [2] 43 45 [2] 5f 6a }

  condition:
    any of them
}