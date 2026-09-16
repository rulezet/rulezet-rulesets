rule TTP_XOR_QUAD_CurrentVersionRun_5ceb {
  strings:
    $key_5ceb = { 0f 84 [2] 2b 8a [2] 00 a6 [2] 2e 84 [2] 3a 9f [2] 35 85 [2] 2b 98 [2] 29 99 [2] 32 9f [2] 2e 98 [2] 32 b7 }

  condition:
    any of them
}