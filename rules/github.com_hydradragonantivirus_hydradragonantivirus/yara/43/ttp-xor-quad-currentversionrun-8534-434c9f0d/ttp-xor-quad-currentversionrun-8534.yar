rule TTP_XOR_QUAD_CurrentVersionRun_8534 {
  strings:
    $key_8534 = { d6 5b [2] f2 55 [2] d9 79 [2] f7 5b [2] e3 40 [2] ec 5a [2] f2 47 [2] f0 46 [2] eb 40 [2] f7 47 [2] eb 68 }

  condition:
    any of them
}