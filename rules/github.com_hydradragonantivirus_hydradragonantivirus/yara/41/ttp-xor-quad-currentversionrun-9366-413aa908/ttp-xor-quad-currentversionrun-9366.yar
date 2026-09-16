rule TTP_XOR_QUAD_CurrentVersionRun_9366 {
  strings:
    $key_9366 = { c0 09 [2] e4 07 [2] cf 2b [2] e1 09 [2] f5 12 [2] fa 08 [2] e4 15 [2] e6 14 [2] fd 12 [2] e1 15 [2] fd 3a }

  condition:
    any of them
}