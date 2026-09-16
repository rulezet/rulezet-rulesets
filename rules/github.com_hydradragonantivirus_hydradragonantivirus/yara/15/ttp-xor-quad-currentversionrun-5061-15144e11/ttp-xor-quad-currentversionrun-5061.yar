rule TTP_XOR_QUAD_CurrentVersionRun_5061 {
  strings:
    $key_5061 = { 03 0e [2] 27 00 [2] 0c 2c [2] 22 0e [2] 36 15 [2] 39 0f [2] 27 12 [2] 25 13 [2] 3e 15 [2] 22 12 [2] 3e 3d }

  condition:
    any of them
}