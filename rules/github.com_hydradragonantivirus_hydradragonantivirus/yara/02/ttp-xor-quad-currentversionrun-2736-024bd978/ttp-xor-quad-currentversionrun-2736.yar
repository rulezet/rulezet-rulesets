rule TTP_XOR_QUAD_CurrentVersionRun_2736 {
  strings:
    $key_2736 = { 74 59 [2] 50 57 [2] 7b 7b [2] 55 59 [2] 41 42 [2] 4e 58 [2] 50 45 [2] 52 44 [2] 49 42 [2] 55 45 [2] 49 6a }

  condition:
    any of them
}