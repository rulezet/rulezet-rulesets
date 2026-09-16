rule TTP_XOR_QUAD_CurrentVersionRun_5c41 {
  strings:
    $key_5c41 = { 0f 2e [2] 2b 20 [2] 00 0c [2] 2e 2e [2] 3a 35 [2] 35 2f [2] 2b 32 [2] 29 33 [2] 32 35 [2] 2e 32 [2] 32 1d }

  condition:
    any of them
}