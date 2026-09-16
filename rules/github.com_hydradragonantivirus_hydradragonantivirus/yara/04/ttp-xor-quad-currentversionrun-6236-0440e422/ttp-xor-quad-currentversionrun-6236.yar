rule TTP_XOR_QUAD_CurrentVersionRun_6236 {
  strings:
    $key_6236 = { 31 59 [2] 15 57 [2] 3e 7b [2] 10 59 [2] 04 42 [2] 0b 58 [2] 15 45 [2] 17 44 [2] 0c 42 [2] 10 45 [2] 0c 6a }

  condition:
    any of them
}