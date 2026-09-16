rule TTP_XOR_QUAD_CurrentVersionRun_9309 {
  strings:
    $key_9309 = { c0 66 [2] e4 68 [2] cf 44 [2] e1 66 [2] f5 7d [2] fa 67 [2] e4 7a [2] e6 7b [2] fd 7d [2] e1 7a [2] fd 55 }

  condition:
    any of them
}