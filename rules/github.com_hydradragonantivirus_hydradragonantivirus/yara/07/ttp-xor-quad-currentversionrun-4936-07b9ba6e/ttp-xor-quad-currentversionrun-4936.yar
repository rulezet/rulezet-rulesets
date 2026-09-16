rule TTP_XOR_QUAD_CurrentVersionRun_4936 {
  strings:
    $key_4936 = { 1a 59 [2] 3e 57 [2] 15 7b [2] 3b 59 [2] 2f 42 [2] 20 58 [2] 3e 45 [2] 3c 44 [2] 27 42 [2] 3b 45 [2] 27 6a }

  condition:
    any of them
}