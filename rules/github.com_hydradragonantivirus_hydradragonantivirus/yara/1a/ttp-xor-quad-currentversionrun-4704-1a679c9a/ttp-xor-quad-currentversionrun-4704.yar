rule TTP_XOR_QUAD_CurrentVersionRun_4704 {
  strings:
    $key_4704 = { 14 6b [2] 30 65 [2] 1b 49 [2] 35 6b [2] 21 70 [2] 2e 6a [2] 30 77 [2] 32 76 [2] 29 70 [2] 35 77 [2] 29 58 }

  condition:
    any of them
}