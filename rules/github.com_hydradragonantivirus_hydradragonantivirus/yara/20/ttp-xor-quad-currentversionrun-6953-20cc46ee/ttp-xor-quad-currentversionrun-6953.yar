rule TTP_XOR_QUAD_CurrentVersionRun_6953 {
  strings:
    $key_6953 = { 3a 3c [2] 1e 32 [2] 35 1e [2] 1b 3c [2] 0f 27 [2] 00 3d [2] 1e 20 [2] 1c 21 [2] 07 27 [2] 1b 20 [2] 07 0f }

  condition:
    any of them
}