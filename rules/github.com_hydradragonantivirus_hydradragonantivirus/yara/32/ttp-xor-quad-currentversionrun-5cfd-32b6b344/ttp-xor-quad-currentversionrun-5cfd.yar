rule TTP_XOR_QUAD_CurrentVersionRun_5cfd {
  strings:
    $key_5cfd = { 0f 92 [2] 2b 9c [2] 00 b0 [2] 2e 92 [2] 3a 89 [2] 35 93 [2] 2b 8e [2] 29 8f [2] 32 89 [2] 2e 8e [2] 32 a1 }

  condition:
    any of them
}