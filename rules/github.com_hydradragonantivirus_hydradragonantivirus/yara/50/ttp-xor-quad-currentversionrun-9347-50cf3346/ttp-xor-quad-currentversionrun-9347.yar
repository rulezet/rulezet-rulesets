rule TTP_XOR_QUAD_CurrentVersionRun_9347 {
  strings:
    $key_9347 = { c0 28 [2] e4 26 [2] cf 0a [2] e1 28 [2] f5 33 [2] fa 29 [2] e4 34 [2] e6 35 [2] fd 33 [2] e1 34 [2] fd 1b }

  condition:
    any of them
}