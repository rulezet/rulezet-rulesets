rule TTP_XOR_QUAD_CurrentVersionRun_5536 {
  strings:
    $key_5536 = { 06 59 [2] 22 57 [2] 09 7b [2] 27 59 [2] 33 42 [2] 3c 58 [2] 22 45 [2] 20 44 [2] 3b 42 [2] 27 45 [2] 3b 6a }

  condition:
    any of them
}