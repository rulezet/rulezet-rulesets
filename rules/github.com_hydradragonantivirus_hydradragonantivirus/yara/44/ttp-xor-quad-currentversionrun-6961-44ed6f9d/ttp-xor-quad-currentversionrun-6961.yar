rule TTP_XOR_QUAD_CurrentVersionRun_6961 {
  strings:
    $key_6961 = { 3a 0e [2] 1e 00 [2] 35 2c [2] 1b 0e [2] 0f 15 [2] 00 0f [2] 1e 12 [2] 1c 13 [2] 07 15 [2] 1b 12 [2] 07 3d }

  condition:
    any of them
}