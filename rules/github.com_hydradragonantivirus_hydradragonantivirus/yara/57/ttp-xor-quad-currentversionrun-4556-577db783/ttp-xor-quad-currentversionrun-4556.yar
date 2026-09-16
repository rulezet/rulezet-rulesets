rule TTP_XOR_QUAD_CurrentVersionRun_4556 {
  strings:
    $key_4556 = { 16 39 [2] 32 37 [2] 19 1b [2] 37 39 [2] 23 22 [2] 2c 38 [2] 32 25 [2] 30 24 [2] 2b 22 [2] 37 25 [2] 2b 0a }

  condition:
    any of them
}