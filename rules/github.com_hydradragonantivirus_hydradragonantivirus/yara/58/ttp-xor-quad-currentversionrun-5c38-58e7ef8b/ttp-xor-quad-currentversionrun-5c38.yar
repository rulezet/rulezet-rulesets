rule TTP_XOR_QUAD_CurrentVersionRun_5c38 {
  strings:
    $key_5c38 = { 0f 57 [2] 2b 59 [2] 00 75 [2] 2e 57 [2] 3a 4c [2] 35 56 [2] 2b 4b [2] 29 4a [2] 32 4c [2] 2e 4b [2] 32 64 }

  condition:
    any of them
}