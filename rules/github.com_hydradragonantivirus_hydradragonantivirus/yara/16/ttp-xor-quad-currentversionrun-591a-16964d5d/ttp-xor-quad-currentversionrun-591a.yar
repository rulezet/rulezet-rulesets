rule TTP_XOR_QUAD_CurrentVersionRun_591a {
  strings:
    $key_591a = { 0a 75 [2] 2e 7b [2] 05 57 [2] 2b 75 [2] 3f 6e [2] 30 74 [2] 2e 69 [2] 2c 68 [2] 37 6e [2] 2b 69 [2] 37 46 }

  condition:
    any of them
}