rule TTP_XOR_QUAD_CurrentVersionRun_822b {
  strings:
    $key_822b = { d1 44 [2] f5 4a [2] de 66 [2] f0 44 [2] e4 5f [2] eb 45 [2] f5 58 [2] f7 59 [2] ec 5f [2] f0 58 [2] ec 77 }

  condition:
    any of them
}