rule TTP_XOR_QUAD_CurrentVersionRun_0736 {
  strings:
    $key_0736 = { 54 59 [2] 70 57 [2] 5b 7b [2] 75 59 [2] 61 42 [2] 6e 58 [2] 70 45 [2] 72 44 [2] 69 42 [2] 75 45 [2] 69 6a }

  condition:
    any of them
}