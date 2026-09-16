rule TTP_XOR_QUAD_CurrentVersionRun_4057 {
  strings:
    $key_4057 = { 13 38 [2] 37 36 [2] 1c 1a [2] 32 38 [2] 26 23 [2] 29 39 [2] 37 24 [2] 35 25 [2] 2e 23 [2] 32 24 [2] 2e 0b }

  condition:
    any of them
}