rule TTP_XOR_QUAD_CurrentVersionRun_9449 {
  strings:
    $key_9449 = { c7 26 [2] e3 28 [2] c8 04 [2] e6 26 [2] f2 3d [2] fd 27 [2] e3 3a [2] e1 3b [2] fa 3d [2] e6 3a [2] fa 15 }

  condition:
    any of them
}