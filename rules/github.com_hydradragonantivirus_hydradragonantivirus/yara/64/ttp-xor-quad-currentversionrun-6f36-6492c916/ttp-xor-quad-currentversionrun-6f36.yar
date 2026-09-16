rule TTP_XOR_QUAD_CurrentVersionRun_6f36 {
  strings:
    $key_6f36 = { 3c 59 [2] 18 57 [2] 33 7b [2] 1d 59 [2] 09 42 [2] 06 58 [2] 18 45 [2] 1a 44 [2] 01 42 [2] 1d 45 [2] 01 6a }

  condition:
    any of them
}