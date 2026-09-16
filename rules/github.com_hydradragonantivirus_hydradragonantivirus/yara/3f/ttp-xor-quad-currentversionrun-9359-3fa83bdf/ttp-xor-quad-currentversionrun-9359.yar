rule TTP_XOR_QUAD_CurrentVersionRun_9359 {
  strings:
    $key_9359 = { c0 36 [2] e4 38 [2] cf 14 [2] e1 36 [2] f5 2d [2] fa 37 [2] e4 2a [2] e6 2b [2] fd 2d [2] e1 2a [2] fd 05 }

  condition:
    any of them
}