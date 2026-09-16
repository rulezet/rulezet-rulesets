rule TTP_XOR_QUAD_CurrentVersionRun_9371 {
  strings:
    $key_9371 = { c0 1e [2] e4 10 [2] cf 3c [2] e1 1e [2] f5 05 [2] fa 1f [2] e4 02 [2] e6 03 [2] fd 05 [2] e1 02 [2] fd 2d }

  condition:
    any of them
}