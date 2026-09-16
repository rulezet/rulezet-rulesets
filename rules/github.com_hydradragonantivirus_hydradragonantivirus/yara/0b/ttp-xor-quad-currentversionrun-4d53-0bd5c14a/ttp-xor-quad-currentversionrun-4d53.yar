rule TTP_XOR_QUAD_CurrentVersionRun_4d53 {
  strings:
    $key_4d53 = { 1e 3c [2] 3a 32 [2] 11 1e [2] 3f 3c [2] 2b 27 [2] 24 3d [2] 3a 20 [2] 38 21 [2] 23 27 [2] 3f 20 [2] 23 0f }

  condition:
    any of them
}