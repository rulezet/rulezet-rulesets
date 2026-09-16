rule TTP_XOR_QUAD_CurrentVersionRun_f546 {
  strings:
    $key_f546 = { a6 29 [2] 82 27 [2] a9 0b [2] 87 29 [2] 93 32 [2] 9c 28 [2] 82 35 [2] 80 34 [2] 9b 32 [2] 87 35 [2] 9b 1a }

  condition:
    any of them
}