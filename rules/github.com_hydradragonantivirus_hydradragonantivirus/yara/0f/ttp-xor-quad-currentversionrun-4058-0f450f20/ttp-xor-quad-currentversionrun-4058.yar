rule TTP_XOR_QUAD_CurrentVersionRun_4058 {
  strings:
    $key_4058 = { 13 37 [2] 37 39 [2] 1c 15 [2] 32 37 [2] 26 2c [2] 29 36 [2] 37 2b [2] 35 2a [2] 2e 2c [2] 32 2b [2] 2e 04 }

  condition:
    any of them
}