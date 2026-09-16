rule TTP_XOR_QUAD_CurrentVersionRun_8218 {
  strings:
    $key_8218 = { d1 77 [2] f5 79 [2] de 55 [2] f0 77 [2] e4 6c [2] eb 76 [2] f5 6b [2] f7 6a [2] ec 6c [2] f0 6b [2] ec 44 }

  condition:
    any of them
}