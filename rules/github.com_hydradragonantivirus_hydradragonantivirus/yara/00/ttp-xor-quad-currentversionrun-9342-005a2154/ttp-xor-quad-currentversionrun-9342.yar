rule TTP_XOR_QUAD_CurrentVersionRun_9342 {
  strings:
    $key_9342 = { c0 2d [2] e4 23 [2] cf 0f [2] e1 2d [2] f5 36 [2] fa 2c [2] e4 31 [2] e6 30 [2] fd 36 [2] e1 31 [2] fd 1e }

  condition:
    any of them
}