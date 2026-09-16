rule TTP_XOR_QUAD_CurrentVersionRun_5906 {
  strings:
    $key_5906 = { 0a 69 [2] 2e 67 [2] 05 4b [2] 2b 69 [2] 3f 72 [2] 30 68 [2] 2e 75 [2] 2c 74 [2] 37 72 [2] 2b 75 [2] 37 5a }

  condition:
    any of them
}