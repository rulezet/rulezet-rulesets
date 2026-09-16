rule TTP_XOR_QUAD_CurrentVersionRun_821b {
  strings:
    $key_821b = { d1 74 [2] f5 7a [2] de 56 [2] f0 74 [2] e4 6f [2] eb 75 [2] f5 68 [2] f7 69 [2] ec 6f [2] f0 68 [2] ec 47 }

  condition:
    any of them
}