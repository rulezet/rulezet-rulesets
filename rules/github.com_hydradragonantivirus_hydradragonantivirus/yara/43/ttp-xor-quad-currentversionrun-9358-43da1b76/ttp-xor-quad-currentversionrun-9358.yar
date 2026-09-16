rule TTP_XOR_QUAD_CurrentVersionRun_9358 {
  strings:
    $key_9358 = { c0 37 [2] e4 39 [2] cf 15 [2] e1 37 [2] f5 2c [2] fa 36 [2] e4 2b [2] e6 2a [2] fd 2c [2] e1 2b [2] fd 04 }

  condition:
    any of them
}