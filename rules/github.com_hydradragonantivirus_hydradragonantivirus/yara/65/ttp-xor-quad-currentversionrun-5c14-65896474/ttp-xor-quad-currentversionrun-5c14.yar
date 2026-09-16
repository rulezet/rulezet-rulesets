rule TTP_XOR_QUAD_CurrentVersionRun_5c14 {
  strings:
    $key_5c14 = { 0f 7b [2] 2b 75 [2] 00 59 [2] 2e 7b [2] 3a 60 [2] 35 7a [2] 2b 67 [2] 29 66 [2] 32 60 [2] 2e 67 [2] 32 48 }

  condition:
    any of them
}