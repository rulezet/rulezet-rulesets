rule TTP_XOR_QUAD_CurrentVersionRun_3736 {
  strings:
    $key_3736 = { 64 59 [2] 40 57 [2] 6b 7b [2] 45 59 [2] 51 42 [2] 5e 58 [2] 40 45 [2] 42 44 [2] 59 42 [2] 45 45 [2] 59 6a }

  condition:
    any of them
}