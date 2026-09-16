rule TTP_XOR_QUAD_CurrentVersionRun_6836 {
  strings:
    $key_6836 = { 3b 59 [2] 1f 57 [2] 34 7b [2] 1a 59 [2] 0e 42 [2] 01 58 [2] 1f 45 [2] 1d 44 [2] 06 42 [2] 1a 45 [2] 06 6a }

  condition:
    any of them
}