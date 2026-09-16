rule TTP_XOR_QUAD_CurrentVersionRun_5c18 {
  strings:
    $key_5c18 = { 0f 77 [2] 2b 79 [2] 00 55 [2] 2e 77 [2] 3a 6c [2] 35 76 [2] 2b 6b [2] 29 6a [2] 32 6c [2] 2e 6b [2] 32 44 }

  condition:
    any of them
}