rule TTP_XOR_QUAD_CurrentVersionRun_2236 {
  strings:
    $key_2236 = { 71 59 [2] 55 57 [2] 7e 7b [2] 50 59 [2] 44 42 [2] 4b 58 [2] 55 45 [2] 57 44 [2] 4c 42 [2] 50 45 [2] 4c 6a }

  condition:
    any of them
}