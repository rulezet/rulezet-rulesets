rule TTP_XOR_QUAD_CurrentVersionRun_5c5c {
  strings:
    $key_5c5c = { 0f 33 [2] 2b 3d [2] 00 11 [2] 2e 33 [2] 3a 28 [2] 35 32 [2] 2b 2f [2] 29 2e [2] 32 28 [2] 2e 2f [2] 32 00 }

  condition:
    any of them
}