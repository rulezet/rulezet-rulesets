rule TTP_XOR_QUAD_CurrentVersionRun_9361 {
  strings:
    $key_9361 = { c0 0e [2] e4 00 [2] cf 2c [2] e1 0e [2] f5 15 [2] fa 0f [2] e4 12 [2] e6 13 [2] fd 15 [2] e1 12 [2] fd 3d }

  condition:
    any of them
}