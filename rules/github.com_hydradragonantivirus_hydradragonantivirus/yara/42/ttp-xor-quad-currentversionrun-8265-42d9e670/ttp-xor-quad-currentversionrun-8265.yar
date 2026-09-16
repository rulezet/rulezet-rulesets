rule TTP_XOR_QUAD_CurrentVersionRun_8265 {
  strings:
    $key_8265 = { d1 0a [2] f5 04 [2] de 28 [2] f0 0a [2] e4 11 [2] eb 0b [2] f5 16 [2] f7 17 [2] ec 11 [2] f0 16 [2] ec 39 }

  condition:
    any of them
}