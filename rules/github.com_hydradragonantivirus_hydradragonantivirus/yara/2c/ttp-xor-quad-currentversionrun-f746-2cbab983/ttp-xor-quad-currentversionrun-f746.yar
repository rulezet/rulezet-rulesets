rule TTP_XOR_QUAD_CurrentVersionRun_f746 {
  strings:
    $key_f746 = { a4 29 [2] 80 27 [2] ab 0b [2] 85 29 [2] 91 32 [2] 9e 28 [2] 80 35 [2] 82 34 [2] 99 32 [2] 85 35 [2] 99 1a }

  condition:
    any of them
}