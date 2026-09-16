rule TTP_XOR_QUAD_CurrentVersionRun_5c53 {
  strings:
    $key_5c53 = { 0f 3c [2] 2b 32 [2] 00 1e [2] 2e 3c [2] 3a 27 [2] 35 3d [2] 2b 20 [2] 29 21 [2] 32 27 [2] 2e 20 [2] 32 0f }

  condition:
    any of them
}