rule TTP_XOR_QUAD_CurrentVersionRun_7556 {
  strings:
    $key_7556 = { 26 39 [2] 02 37 [2] 29 1b [2] 07 39 [2] 13 22 [2] 1c 38 [2] 02 25 [2] 00 24 [2] 1b 22 [2] 07 25 [2] 1b 0a }

  condition:
    any of them
}