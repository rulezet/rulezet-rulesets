rule TTP_XOR_QUAD_CurrentVersionRun_5c05 {
  strings:
    $key_5c05 = { 0f 6a [2] 2b 64 [2] 00 48 [2] 2e 6a [2] 3a 71 [2] 35 6b [2] 2b 76 [2] 29 77 [2] 32 71 [2] 2e 76 [2] 32 59 }

  condition:
    any of them
}