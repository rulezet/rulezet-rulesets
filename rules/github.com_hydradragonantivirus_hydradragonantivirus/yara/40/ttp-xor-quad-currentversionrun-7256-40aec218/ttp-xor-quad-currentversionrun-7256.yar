rule TTP_XOR_QUAD_CurrentVersionRun_7256 {
  strings:
    $key_7256 = { 21 39 [2] 05 37 [2] 2e 1b [2] 00 39 [2] 14 22 [2] 1b 38 [2] 05 25 [2] 07 24 [2] 1c 22 [2] 00 25 [2] 1c 0a }

  condition:
    any of them
}