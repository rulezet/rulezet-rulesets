rule TTP_XOR_QUAD_CurrentVersionRun_9327 {
  strings:
    $key_9327 = { c0 48 [2] e4 46 [2] cf 6a [2] e1 48 [2] f5 53 [2] fa 49 [2] e4 54 [2] e6 55 [2] fd 53 [2] e1 54 [2] fd 7b }

  condition:
    any of them
}