rule TTP_XOR_QUAD_CurrentVersionRun_5c22 {
  strings:
    $key_5c22 = { 0f 4d [2] 2b 43 [2] 00 6f [2] 2e 4d [2] 3a 56 [2] 35 4c [2] 2b 51 [2] 29 50 [2] 32 56 [2] 2e 51 [2] 32 7e }

  condition:
    any of them
}