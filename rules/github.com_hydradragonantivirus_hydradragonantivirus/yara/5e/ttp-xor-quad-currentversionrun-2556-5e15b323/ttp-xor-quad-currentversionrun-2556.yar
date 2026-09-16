rule TTP_XOR_QUAD_CurrentVersionRun_2556 {
  strings:
    $key_2556 = { 76 39 [2] 52 37 [2] 79 1b [2] 57 39 [2] 43 22 [2] 4c 38 [2] 52 25 [2] 50 24 [2] 4b 22 [2] 57 25 [2] 4b 0a }

  condition:
    any of them
}