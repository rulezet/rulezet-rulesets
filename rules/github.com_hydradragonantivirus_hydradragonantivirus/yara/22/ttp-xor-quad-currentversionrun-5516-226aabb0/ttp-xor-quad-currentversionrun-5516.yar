rule TTP_XOR_QUAD_CurrentVersionRun_5516 {
  strings:
    $key_5516 = { 06 79 [2] 22 77 [2] 09 5b [2] 27 79 [2] 33 62 [2] 3c 78 [2] 22 65 [2] 20 64 [2] 3b 62 [2] 27 65 [2] 3b 4a }

  condition:
    any of them
}