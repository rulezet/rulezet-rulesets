rule TTP_XOR_QUAD_CurrentVersionRun_0236 {
  strings:
    $key_0236 = { 51 59 [2] 75 57 [2] 5e 7b [2] 70 59 [2] 64 42 [2] 6b 58 [2] 75 45 [2] 77 44 [2] 6c 42 [2] 70 45 [2] 6c 6a }

  condition:
    any of them
}