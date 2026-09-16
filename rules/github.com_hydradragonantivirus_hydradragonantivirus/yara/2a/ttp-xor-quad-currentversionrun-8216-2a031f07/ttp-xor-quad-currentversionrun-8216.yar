rule TTP_XOR_QUAD_CurrentVersionRun_8216 {
  strings:
    $key_8216 = { d1 79 [2] f5 77 [2] de 5b [2] f0 79 [2] e4 62 [2] eb 78 [2] f5 65 [2] f7 64 [2] ec 62 [2] f0 65 [2] ec 4a }

  condition:
    any of them
}