rule TTP_XOR_QUAD_CurrentVersionRun_9354 {
  strings:
    $key_9354 = { c0 3b [2] e4 35 [2] cf 19 [2] e1 3b [2] f5 20 [2] fa 3a [2] e4 27 [2] e6 26 [2] fd 20 [2] e1 27 [2] fd 08 }

  condition:
    any of them
}