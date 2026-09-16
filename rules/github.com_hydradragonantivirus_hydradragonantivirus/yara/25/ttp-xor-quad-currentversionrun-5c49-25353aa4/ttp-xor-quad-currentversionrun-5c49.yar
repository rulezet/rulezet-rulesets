rule TTP_XOR_QUAD_CurrentVersionRun_5c49 {
  strings:
    $key_5c49 = { 0f 26 [2] 2b 28 [2] 00 04 [2] 2e 26 [2] 3a 3d [2] 35 27 [2] 2b 3a [2] 29 3b [2] 32 3d [2] 2e 3a [2] 32 15 }

  condition:
    any of them
}