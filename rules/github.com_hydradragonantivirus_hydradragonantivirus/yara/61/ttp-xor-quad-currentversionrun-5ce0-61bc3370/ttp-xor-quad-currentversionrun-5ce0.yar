rule TTP_XOR_QUAD_CurrentVersionRun_5ce0 {
  strings:
    $key_5ce0 = { 0f 8f [2] 2b 81 [2] 00 ad [2] 2e 8f [2] 3a 94 [2] 35 8e [2] 2b 93 [2] 29 92 [2] 32 94 [2] 2e 93 [2] 32 bc }

  condition:
    any of them
}