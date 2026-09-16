rule TTP_XOR_QUAD_CurrentVersionRun_5c33 {
  strings:
    $key_5c33 = { 0f 5c [2] 2b 52 [2] 00 7e [2] 2e 5c [2] 3a 47 [2] 35 5d [2] 2b 40 [2] 29 41 [2] 32 47 [2] 2e 40 [2] 32 6f }

  condition:
    any of them
}