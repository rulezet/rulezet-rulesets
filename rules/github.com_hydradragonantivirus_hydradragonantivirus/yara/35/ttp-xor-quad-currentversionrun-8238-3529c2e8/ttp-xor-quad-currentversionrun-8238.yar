rule TTP_XOR_QUAD_CurrentVersionRun_8238 {
  strings:
    $key_8238 = { d1 57 [2] f5 59 [2] de 75 [2] f0 57 [2] e4 4c [2] eb 56 [2] f5 4b [2] f7 4a [2] ec 4c [2] f0 4b [2] ec 64 }

  condition:
    any of them
}