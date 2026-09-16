rule TTP_XOR_QUAD_CurrentVersionRun_8239 {
  strings:
    $key_8239 = { d1 56 [2] f5 58 [2] de 74 [2] f0 56 [2] e4 4d [2] eb 57 [2] f5 4a [2] f7 4b [2] ec 4d [2] f0 4a [2] ec 65 }

  condition:
    any of them
}