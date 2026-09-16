rule TTP_XOR_QUAD_CurrentVersionRun_f236 {
  strings:
    $key_f236 = { a1 59 [2] 85 57 [2] ae 7b [2] 80 59 [2] 94 42 [2] 9b 58 [2] 85 45 [2] 87 44 [2] 9c 42 [2] 80 45 [2] 9c 6a }

  condition:
    any of them
}