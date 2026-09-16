rule TTP_XOR_QUAD_CurrentVersionRun_4705 {
  strings:
    $key_4705 = { 14 6a [2] 30 64 [2] 1b 48 [2] 35 6a [2] 21 71 [2] 2e 6b [2] 30 76 [2] 32 77 [2] 29 71 [2] 35 76 [2] 29 59 }

  condition:
    any of them
}