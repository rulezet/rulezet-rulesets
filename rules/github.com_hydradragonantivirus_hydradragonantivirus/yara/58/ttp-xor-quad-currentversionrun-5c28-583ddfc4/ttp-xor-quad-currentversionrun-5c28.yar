rule TTP_XOR_QUAD_CurrentVersionRun_5c28 {
  strings:
    $key_5c28 = { 0f 47 [2] 2b 49 [2] 00 65 [2] 2e 47 [2] 3a 5c [2] 35 46 [2] 2b 5b [2] 29 5a [2] 32 5c [2] 2e 5b [2] 32 74 }

  condition:
    any of them
}