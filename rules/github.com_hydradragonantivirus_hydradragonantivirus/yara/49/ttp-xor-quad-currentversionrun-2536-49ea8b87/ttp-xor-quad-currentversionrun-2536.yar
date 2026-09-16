rule TTP_XOR_QUAD_CurrentVersionRun_2536 {
  strings:
    $key_2536 = { 76 59 [2] 52 57 [2] 79 7b [2] 57 59 [2] 43 42 [2] 4c 58 [2] 52 45 [2] 50 44 [2] 4b 42 [2] 57 45 [2] 4b 6a }

  condition:
    any of them
}