rule TTP_XOR_QUAD_CurrentVersionRun_855e {
  strings:
    $key_855e = { d6 31 [2] f2 3f [2] d9 13 [2] f7 31 [2] e3 2a [2] ec 30 [2] f2 2d [2] f0 2c [2] eb 2a [2] f7 2d [2] eb 02 }

  condition:
    any of them
}