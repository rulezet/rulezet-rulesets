rule TTP_XOR_QUAD_CurrentVersionRun_8554 {
  strings:
    $key_8554 = { d6 3b [2] f2 35 [2] d9 19 [2] f7 3b [2] e3 20 [2] ec 3a [2] f2 27 [2] f0 26 [2] eb 20 [2] f7 27 [2] eb 08 }

  condition:
    any of them
}