rule TTP_XOR_QUAD_CurrentVersionRun_8579 {
  strings:
    $key_8579 = { d6 16 [2] f2 18 [2] d9 34 [2] f7 16 [2] e3 0d [2] ec 17 [2] f2 0a [2] f0 0b [2] eb 0d [2] f7 0a [2] eb 25 }

  condition:
    any of them
}