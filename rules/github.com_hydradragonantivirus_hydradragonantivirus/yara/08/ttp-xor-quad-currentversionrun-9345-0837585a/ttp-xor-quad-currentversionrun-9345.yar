rule TTP_XOR_QUAD_CurrentVersionRun_9345 {
  strings:
    $key_9345 = { c0 2a [2] e4 24 [2] cf 08 [2] e1 2a [2] f5 31 [2] fa 2b [2] e4 36 [2] e6 37 [2] fd 31 [2] e1 36 [2] fd 19 }

  condition:
    any of them
}