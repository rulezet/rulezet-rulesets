rule TTP_XOR_QUAD_CurrentVersionRun_5c21 {
  strings:
    $key_5c21 = { 0f 4e [2] 2b 40 [2] 00 6c [2] 2e 4e [2] 3a 55 [2] 35 4f [2] 2b 52 [2] 29 53 [2] 32 55 [2] 2e 52 [2] 32 7d }

  condition:
    any of them
}