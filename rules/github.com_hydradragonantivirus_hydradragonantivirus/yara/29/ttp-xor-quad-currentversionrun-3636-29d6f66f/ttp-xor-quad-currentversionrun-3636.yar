rule TTP_XOR_QUAD_CurrentVersionRun_3636 {
  strings:
    $key_3636 = { 65 59 [2] 41 57 [2] 6a 7b [2] 44 59 [2] 50 42 [2] 5f 58 [2] 41 45 [2] 43 44 [2] 58 42 [2] 44 45 [2] 58 6a }

  condition:
    any of them
}