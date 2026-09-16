rule TTP_XOR_QUAD_CurrentVersionRun_4061 {
  strings:
    $key_4061 = { 13 0e [2] 37 00 [2] 1c 2c [2] 32 0e [2] 26 15 [2] 29 0f [2] 37 12 [2] 35 13 [2] 2e 15 [2] 32 12 [2] 2e 3d }

  condition:
    any of them
}