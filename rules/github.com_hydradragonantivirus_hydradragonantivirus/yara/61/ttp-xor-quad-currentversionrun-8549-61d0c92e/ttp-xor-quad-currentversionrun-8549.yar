rule TTP_XOR_QUAD_CurrentVersionRun_8549 {
  strings:
    $key_8549 = { d6 26 [2] f2 28 [2] d9 04 [2] f7 26 [2] e3 3d [2] ec 27 [2] f2 3a [2] f0 3b [2] eb 3d [2] f7 3a [2] eb 15 }

  condition:
    any of them
}