rule TTP_XOR_QUAD_CurrentVersionRun_852b {
  strings:
    $key_852b = { d6 44 [2] f2 4a [2] d9 66 [2] f7 44 [2] e3 5f [2] ec 45 [2] f2 58 [2] f0 59 [2] eb 5f [2] f7 58 [2] eb 77 }

  condition:
    any of them
}