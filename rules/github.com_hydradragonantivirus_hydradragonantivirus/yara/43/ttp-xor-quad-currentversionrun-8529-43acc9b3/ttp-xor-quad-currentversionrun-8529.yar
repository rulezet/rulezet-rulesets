rule TTP_XOR_QUAD_CurrentVersionRun_8529 {
  strings:
    $key_8529 = { d6 46 [2] f2 48 [2] d9 64 [2] f7 46 [2] e3 5d [2] ec 47 [2] f2 5a [2] f0 5b [2] eb 5d [2] f7 5a [2] eb 75 }

  condition:
    any of them
}