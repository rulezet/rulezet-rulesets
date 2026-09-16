rule TTP_XOR_QUAD_CurrentVersionRun_5cfc {
  strings:
    $key_5cfc = { 0f 93 [2] 2b 9d [2] 00 b1 [2] 2e 93 [2] 3a 88 [2] 35 92 [2] 2b 8f [2] 29 8e [2] 32 88 [2] 2e 8f [2] 32 a0 }

  condition:
    any of them
}