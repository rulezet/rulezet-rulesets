rule TTP_XOR_QUAD_CurrentVersionRun_5c15 {
  strings:
    $key_5c15 = { 0f 7a [2] 2b 74 [2] 00 58 [2] 2e 7a [2] 3a 61 [2] 35 7b [2] 2b 66 [2] 29 67 [2] 32 61 [2] 2e 66 [2] 32 49 }

  condition:
    any of them
}