rule TTP_XOR_QUAD_CurrentVersionRun_8553 {
  strings:
    $key_8553 = { d6 3c [2] f2 32 [2] d9 1e [2] f7 3c [2] e3 27 [2] ec 3d [2] f2 20 [2] f0 21 [2] eb 27 [2] f7 20 [2] eb 0f }

  condition:
    any of them
}