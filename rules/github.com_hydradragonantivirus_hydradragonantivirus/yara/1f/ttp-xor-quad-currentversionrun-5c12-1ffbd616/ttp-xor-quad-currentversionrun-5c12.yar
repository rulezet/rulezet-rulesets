rule TTP_XOR_QUAD_CurrentVersionRun_5c12 {
  strings:
    $key_5c12 = { 0f 7d [2] 2b 73 [2] 00 5f [2] 2e 7d [2] 3a 66 [2] 35 7c [2] 2b 61 [2] 29 60 [2] 32 66 [2] 2e 61 [2] 32 4e }

  condition:
    any of them
}