rule TTP_XOR_QUAD_CurrentVersionRun_9303 {
  strings:
    $key_9303 = { c0 6c [2] e4 62 [2] cf 4e [2] e1 6c [2] f5 77 [2] fa 6d [2] e4 70 [2] e6 71 [2] fd 77 [2] e1 70 [2] fd 5f }

  condition:
    any of them
}