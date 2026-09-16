rule TTP_XOR_QUAD_CurrentVersionRun_e161 {
  strings:
    $key_e161 = { b2 0e [2] 96 00 [2] bd 2c [2] 93 0e [2] 87 15 [2] 88 0f [2] 96 12 [2] 94 13 [2] 8f 15 [2] 93 12 [2] 8f 3d }

  condition:
    any of them
}