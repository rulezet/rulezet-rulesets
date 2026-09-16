rule TTP_XOR_QUAD_CurrentVersionRun_4064 {
  strings:
    $key_4064 = { 13 0b [2] 37 05 [2] 1c 29 [2] 32 0b [2] 26 10 [2] 29 0a [2] 37 17 [2] 35 16 [2] 2e 10 [2] 32 17 [2] 2e 38 }

  condition:
    any of them
}