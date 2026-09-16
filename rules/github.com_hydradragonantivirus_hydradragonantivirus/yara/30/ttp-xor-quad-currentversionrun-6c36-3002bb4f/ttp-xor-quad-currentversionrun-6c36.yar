rule TTP_XOR_QUAD_CurrentVersionRun_6c36 {
  strings:
    $key_6c36 = { 3f 59 [2] 1b 57 [2] 30 7b [2] 1e 59 [2] 0a 42 [2] 05 58 [2] 1b 45 [2] 19 44 [2] 02 42 [2] 1e 45 [2] 02 6a }

  condition:
    any of them
}