rule TTP_XOR_QUAD_CurrentVersionRun_7253 {
  strings:
    $key_7253 = { 21 3c [2] 05 32 [2] 2e 1e [2] 00 3c [2] 14 27 [2] 1b 3d [2] 05 20 [2] 07 21 [2] 1c 27 [2] 00 20 [2] 1c 0f }

  condition:
    any of them
}