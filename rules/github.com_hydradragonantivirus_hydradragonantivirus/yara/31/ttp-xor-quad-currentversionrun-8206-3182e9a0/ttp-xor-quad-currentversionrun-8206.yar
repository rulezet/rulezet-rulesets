rule TTP_XOR_QUAD_CurrentVersionRun_8206 {
  strings:
    $key_8206 = { d1 69 [2] f5 67 [2] de 4b [2] f0 69 [2] e4 72 [2] eb 68 [2] f5 75 [2] f7 74 [2] ec 72 [2] f0 75 [2] ec 5a }

  condition:
    any of them
}