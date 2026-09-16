rule TTP_XOR_QUAD_CurrentVersionRun_8574 {
  strings:
    $key_8574 = { d6 1b [2] f2 15 [2] d9 39 [2] f7 1b [2] e3 00 [2] ec 1a [2] f2 07 [2] f0 06 [2] eb 00 [2] f7 07 [2] eb 28 }

  condition:
    any of them
}