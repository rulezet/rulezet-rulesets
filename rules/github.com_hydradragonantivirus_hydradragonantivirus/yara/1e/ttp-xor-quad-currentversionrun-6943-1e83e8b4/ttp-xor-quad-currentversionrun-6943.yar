rule TTP_XOR_QUAD_CurrentVersionRun_6943 {
  strings:
    $key_6943 = { 3a 2c [2] 1e 22 [2] 35 0e [2] 1b 2c [2] 0f 37 [2] 00 2d [2] 1e 30 [2] 1c 31 [2] 07 37 [2] 1b 30 [2] 07 1f }

  condition:
    any of them
}