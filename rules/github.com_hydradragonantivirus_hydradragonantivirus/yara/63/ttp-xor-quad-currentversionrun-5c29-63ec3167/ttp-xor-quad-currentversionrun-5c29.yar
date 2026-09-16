rule TTP_XOR_QUAD_CurrentVersionRun_5c29 {
  strings:
    $key_5c29 = { 0f 46 [2] 2b 48 [2] 00 64 [2] 2e 46 [2] 3a 5d [2] 35 47 [2] 2b 5a [2] 29 5b [2] 32 5d [2] 2e 5a [2] 32 75 }

  condition:
    any of them
}