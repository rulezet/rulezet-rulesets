rule TTP_XOR_QUAD_CurrentVersionRun_9377 {
  strings:
    $key_9377 = { c0 18 [2] e4 16 [2] cf 3a [2] e1 18 [2] f5 03 [2] fa 19 [2] e4 04 [2] e6 05 [2] fd 03 [2] e1 04 [2] fd 2b }

  condition:
    any of them
}