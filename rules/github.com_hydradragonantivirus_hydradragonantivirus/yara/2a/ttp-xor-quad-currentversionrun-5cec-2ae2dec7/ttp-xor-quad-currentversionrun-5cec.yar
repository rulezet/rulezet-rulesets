rule TTP_XOR_QUAD_CurrentVersionRun_5cec {
  strings:
    $key_5cec = { 0f 83 [2] 2b 8d [2] 00 a1 [2] 2e 83 [2] 3a 98 [2] 35 82 [2] 2b 9f [2] 29 9e [2] 32 98 [2] 2e 9f [2] 32 b0 }

  condition:
    any of them
}