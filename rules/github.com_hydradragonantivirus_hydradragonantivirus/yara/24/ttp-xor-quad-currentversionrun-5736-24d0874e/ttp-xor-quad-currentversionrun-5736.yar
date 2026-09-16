rule TTP_XOR_QUAD_CurrentVersionRun_5736 {
  strings:
    $key_5736 = { 04 59 [2] 20 57 [2] 0b 7b [2] 25 59 [2] 31 42 [2] 3e 58 [2] 20 45 [2] 22 44 [2] 39 42 [2] 25 45 [2] 39 6a }

  condition:
    any of them
}