rule TTP_XOR_QUAD_CurrentVersionRun_9353 {
  strings:
    $key_9353 = { c0 3c [2] e4 32 [2] cf 1e [2] e1 3c [2] f5 27 [2] fa 3d [2] e4 20 [2] e6 21 [2] fd 27 [2] e1 20 [2] fd 0f }

  condition:
    any of them
}