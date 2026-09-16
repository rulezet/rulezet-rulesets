rule TTP_XOR_QUAD_CurrentVersionRun_854b {
  strings:
    $key_854b = { d6 24 [2] f2 2a [2] d9 06 [2] f7 24 [2] e3 3f [2] ec 25 [2] f2 38 [2] f0 39 [2] eb 3f [2] f7 38 [2] eb 17 }

  condition:
    any of them
}