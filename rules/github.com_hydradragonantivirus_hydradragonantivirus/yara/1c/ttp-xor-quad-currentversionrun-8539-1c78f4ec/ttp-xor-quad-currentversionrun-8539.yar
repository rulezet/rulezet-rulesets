rule TTP_XOR_QUAD_CurrentVersionRun_8539 {
  strings:
    $key_8539 = { d6 56 [2] f2 58 [2] d9 74 [2] f7 56 [2] e3 4d [2] ec 57 [2] f2 4a [2] f0 4b [2] eb 4d [2] f7 4a [2] eb 65 }

  condition:
    any of them
}