rule TTP_XOR_QUAD_CurrentVersionRun_8524 {
  strings:
    $key_8524 = { d6 4b [2] f2 45 [2] d9 69 [2] f7 4b [2] e3 50 [2] ec 4a [2] f2 57 [2] f0 56 [2] eb 50 [2] f7 57 [2] eb 78 }

  condition:
    any of them
}