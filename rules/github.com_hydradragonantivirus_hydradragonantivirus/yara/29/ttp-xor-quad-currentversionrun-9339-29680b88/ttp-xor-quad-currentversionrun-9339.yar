rule TTP_XOR_QUAD_CurrentVersionRun_9339 {
  strings:
    $key_9339 = { c0 56 [2] e4 58 [2] cf 74 [2] e1 56 [2] f5 4d [2] fa 57 [2] e4 4a [2] e6 4b [2] fd 4d [2] e1 4a [2] fd 65 }

  condition:
    any of them
}