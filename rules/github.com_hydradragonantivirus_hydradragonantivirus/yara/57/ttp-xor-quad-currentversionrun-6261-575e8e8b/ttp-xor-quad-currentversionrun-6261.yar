rule TTP_XOR_QUAD_CurrentVersionRun_6261 {
  strings:
    $key_6261 = { 31 0e [2] 15 00 [2] 3e 2c [2] 10 0e [2] 04 15 [2] 0b 0f [2] 15 12 [2] 17 13 [2] 0c 15 [2] 10 12 [2] 0c 3d }

  condition:
    any of them
}