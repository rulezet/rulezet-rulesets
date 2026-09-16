rule TTP_XOR_QUAD_CurrentVersionRun_8237 {
  strings:
    $key_8237 = { d1 58 [2] f5 56 [2] de 7a [2] f0 58 [2] e4 43 [2] eb 59 [2] f5 44 [2] f7 45 [2] ec 43 [2] f0 44 [2] ec 6b }

  condition:
    any of them
}