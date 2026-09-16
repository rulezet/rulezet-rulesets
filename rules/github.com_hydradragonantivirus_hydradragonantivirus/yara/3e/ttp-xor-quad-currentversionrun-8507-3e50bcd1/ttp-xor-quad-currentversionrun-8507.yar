rule TTP_XOR_QUAD_CurrentVersionRun_8507 {
  strings:
    $key_8507 = { d6 68 [2] f2 66 [2] d9 4a [2] f7 68 [2] e3 73 [2] ec 69 [2] f2 74 [2] f0 75 [2] eb 73 [2] f7 74 [2] eb 5b }

  condition:
    any of them
}