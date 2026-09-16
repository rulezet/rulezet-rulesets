rule TTP_XOR_QUAD_CurrentVersionRun_2557 {
  strings:
    $key_2557 = { 76 38 [2] 52 36 [2] 79 1a [2] 57 38 [2] 43 23 [2] 4c 39 [2] 52 24 [2] 50 25 [2] 4b 23 [2] 57 24 [2] 4b 0b }

  condition:
    any of them
}