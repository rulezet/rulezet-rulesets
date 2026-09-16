rule TTP_XOR_QUAD_CurrentVersionRun_5ce1 {
  strings:
    $key_5ce1 = { 0f 8e [2] 2b 80 [2] 00 ac [2] 2e 8e [2] 3a 95 [2] 35 8f [2] 2b 92 [2] 29 93 [2] 32 95 [2] 2e 92 [2] 32 bd }

  condition:
    any of them
}