rule TTP_XOR_QUAD_CurrentVersionRun_934b {
  strings:
    $key_934b = { c0 24 [2] e4 2a [2] cf 06 [2] e1 24 [2] f5 3f [2] fa 25 [2] e4 38 [2] e6 39 [2] fd 3f [2] e1 38 [2] fd 17 }

  condition:
    any of them
}