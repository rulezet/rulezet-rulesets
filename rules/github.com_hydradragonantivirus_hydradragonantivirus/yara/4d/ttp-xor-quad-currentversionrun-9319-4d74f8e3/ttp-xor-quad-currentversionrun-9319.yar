rule TTP_XOR_QUAD_CurrentVersionRun_9319 {
  strings:
    $key_9319 = { c0 76 [2] e4 78 [2] cf 54 [2] e1 76 [2] f5 6d [2] fa 77 [2] e4 6a [2] e6 6b [2] fd 6d [2] e1 6a [2] fd 45 }

  condition:
    any of them
}