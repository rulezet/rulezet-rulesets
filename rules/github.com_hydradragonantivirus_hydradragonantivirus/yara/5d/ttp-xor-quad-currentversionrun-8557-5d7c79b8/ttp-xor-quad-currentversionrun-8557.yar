rule TTP_XOR_QUAD_CurrentVersionRun_8557 {
  strings:
    $key_8557 = { d6 38 [2] f2 36 [2] d9 1a [2] f7 38 [2] e3 23 [2] ec 39 [2] f2 24 [2] f0 25 [2] eb 23 [2] f7 24 [2] eb 0b }

  condition:
    any of them
}