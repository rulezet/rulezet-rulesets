rule TTP_XOR_QUAD_CurrentVersionRun_3e56 {
  strings:
    $key_3e56 = { 6d 39 [2] 49 37 [2] 62 1b [2] 4c 39 [2] 58 22 [2] 57 38 [2] 49 25 [2] 4b 24 [2] 50 22 [2] 4c 25 [2] 50 0a }

  condition:
    any of them
}