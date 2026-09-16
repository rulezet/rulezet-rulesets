rule TTP_XOR_QUAD_CurrentVersionRun_3436 {
  strings:
    $key_3436 = { 67 59 [2] 43 57 [2] 68 7b [2] 46 59 [2] 52 42 [2] 5d 58 [2] 43 45 [2] 41 44 [2] 5a 42 [2] 46 45 [2] 5a 6a }

  condition:
    any of them
}