rule TTP_XOR_QUAD_CurrentVersionRun_0b36 {
  strings:
    $key_0b36 = { 58 59 [2] 7c 57 [2] 57 7b [2] 79 59 [2] 6d 42 [2] 62 58 [2] 7c 45 [2] 7e 44 [2] 65 42 [2] 79 45 [2] 65 6a }

  condition:
    any of them
}