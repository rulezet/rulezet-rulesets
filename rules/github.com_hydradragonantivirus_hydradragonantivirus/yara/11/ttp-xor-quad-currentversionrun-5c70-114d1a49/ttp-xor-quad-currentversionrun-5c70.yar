rule TTP_XOR_QUAD_CurrentVersionRun_5c70 {
  strings:
    $key_5c70 = { 0f 1f [2] 2b 11 [2] 00 3d [2] 2e 1f [2] 3a 04 [2] 35 1e [2] 2b 03 [2] 29 02 [2] 32 04 [2] 2e 03 [2] 32 2c }

  condition:
    any of them
}