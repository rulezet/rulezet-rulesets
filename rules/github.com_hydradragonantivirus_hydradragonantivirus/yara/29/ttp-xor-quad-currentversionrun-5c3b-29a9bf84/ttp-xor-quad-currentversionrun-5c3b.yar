rule TTP_XOR_QUAD_CurrentVersionRun_5c3b {
  strings:
    $key_5c3b = { 0f 54 [2] 2b 5a [2] 00 76 [2] 2e 54 [2] 3a 4f [2] 35 55 [2] 2b 48 [2] 29 49 [2] 32 4f [2] 2e 48 [2] 32 67 }

  condition:
    any of them
}