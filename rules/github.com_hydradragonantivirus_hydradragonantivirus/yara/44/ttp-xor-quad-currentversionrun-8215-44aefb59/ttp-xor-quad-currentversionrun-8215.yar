rule TTP_XOR_QUAD_CurrentVersionRun_8215 {
  strings:
    $key_8215 = { d1 7a [2] f5 74 [2] de 58 [2] f0 7a [2] e4 61 [2] eb 7b [2] f5 66 [2] f7 67 [2] ec 61 [2] f0 66 [2] ec 49 }

  condition:
    any of them
}