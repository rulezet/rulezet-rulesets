rule TTP_XOR_QUAD_CurrentVersionRun_8575 {
  strings:
    $key_8575 = { d6 1a [2] f2 14 [2] d9 38 [2] f7 1a [2] e3 01 [2] ec 1b [2] f2 06 [2] f0 07 [2] eb 01 [2] f7 06 [2] eb 29 }

  condition:
    any of them
}