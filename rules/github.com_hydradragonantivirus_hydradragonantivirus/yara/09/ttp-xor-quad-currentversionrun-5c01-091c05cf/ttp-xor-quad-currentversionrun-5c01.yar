rule TTP_XOR_QUAD_CurrentVersionRun_5c01 {
  strings:
    $key_5c01 = { 0f 6e [2] 2b 60 [2] 00 4c [2] 2e 6e [2] 3a 75 [2] 35 6f [2] 2b 72 [2] 29 73 [2] 32 75 [2] 2e 72 [2] 32 5d }

  condition:
    any of them
}