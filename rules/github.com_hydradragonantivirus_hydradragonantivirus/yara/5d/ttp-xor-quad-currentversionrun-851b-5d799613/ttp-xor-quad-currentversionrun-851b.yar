rule TTP_XOR_QUAD_CurrentVersionRun_851b {
  strings:
    $key_851b = { d6 74 [2] f2 7a [2] d9 56 [2] f7 74 [2] e3 6f [2] ec 75 [2] f2 68 [2] f0 69 [2] eb 6f [2] f7 68 [2] eb 47 }

  condition:
    any of them
}