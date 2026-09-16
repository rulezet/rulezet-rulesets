rule TTP_XOR_QUAD_CurrentVersionRun_5836 {
  strings:
    $key_5836 = { 0b 59 [2] 2f 57 [2] 04 7b [2] 2a 59 [2] 3e 42 [2] 31 58 [2] 2f 45 [2] 2d 44 [2] 36 42 [2] 2a 45 [2] 36 6a }

  condition:
    any of them
}