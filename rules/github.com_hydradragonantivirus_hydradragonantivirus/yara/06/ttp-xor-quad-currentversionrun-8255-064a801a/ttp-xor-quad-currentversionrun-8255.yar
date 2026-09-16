rule TTP_XOR_QUAD_CurrentVersionRun_8255 {
  strings:
    $key_8255 = { d1 3a [2] f5 34 [2] de 18 [2] f0 3a [2] e4 21 [2] eb 3b [2] f5 26 [2] f7 27 [2] ec 21 [2] f0 26 [2] ec 09 }

  condition:
    any of them
}