rule TTP_XOR_QUAD_CurrentVersionRun_5c2a {
  strings:
    $key_5c2a = { 0f 45 [2] 2b 4b [2] 00 67 [2] 2e 45 [2] 3a 5e [2] 35 44 [2] 2b 59 [2] 29 58 [2] 32 5e [2] 2e 59 [2] 32 76 }

  condition:
    any of them
}