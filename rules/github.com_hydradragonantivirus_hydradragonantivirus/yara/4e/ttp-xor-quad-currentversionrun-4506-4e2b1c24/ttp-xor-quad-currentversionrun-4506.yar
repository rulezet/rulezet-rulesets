rule TTP_XOR_QUAD_CurrentVersionRun_4506 {
  strings:
    $key_4506 = { 16 69 [2] 32 67 [2] 19 4b [2] 37 69 [2] 23 72 [2] 2c 68 [2] 32 75 [2] 30 74 [2] 2b 72 [2] 37 75 [2] 2b 5a }

  condition:
    any of them
}