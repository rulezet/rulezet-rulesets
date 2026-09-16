rule TTP_XOR_QUAD_CurrentVersionRun_5c35 {
  strings:
    $key_5c35 = { 0f 5a [2] 2b 54 [2] 00 78 [2] 2e 5a [2] 3a 41 [2] 35 5b [2] 2b 46 [2] 29 47 [2] 32 41 [2] 2e 46 [2] 32 69 }

  condition:
    any of them
}