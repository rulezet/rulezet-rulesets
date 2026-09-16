rule TTP_XOR_QUAD_CurrentVersionRun_7d05 {
  strings:
    $key_7d05 = { 2e 6a [2] 0a 64 [2] 21 48 [2] 0f 6a [2] 1b 71 [2] 14 6b [2] 0a 76 [2] 08 77 [2] 13 71 [2] 0f 76 [2] 13 59 }

  condition:
    any of them
}