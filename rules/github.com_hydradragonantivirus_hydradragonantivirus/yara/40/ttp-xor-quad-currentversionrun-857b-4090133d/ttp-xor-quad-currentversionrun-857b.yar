rule TTP_XOR_QUAD_CurrentVersionRun_857b {
  strings:
    $key_857b = { d6 14 [2] f2 1a [2] d9 36 [2] f7 14 [2] e3 0f [2] ec 15 [2] f2 08 [2] f0 09 [2] eb 0f [2] f7 08 [2] eb 27 }

  condition:
    any of them
}