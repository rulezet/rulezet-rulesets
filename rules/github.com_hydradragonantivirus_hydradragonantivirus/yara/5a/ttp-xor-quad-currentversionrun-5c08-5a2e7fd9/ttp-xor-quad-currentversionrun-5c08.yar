rule TTP_XOR_QUAD_CurrentVersionRun_5c08 {
  strings:
    $key_5c08 = { 0f 67 [2] 2b 69 [2] 00 45 [2] 2e 67 [2] 3a 7c [2] 35 66 [2] 2b 7b [2] 29 7a [2] 32 7c [2] 2e 7b [2] 32 54 }

  condition:
    any of them
}