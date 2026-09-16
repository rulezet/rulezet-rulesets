rule TTP_XOR_QUAD_CurrentVersionRun_85e5 {
  strings:
    $key_85e5 = { d6 8a [2] f2 84 [2] d9 a8 [2] f7 8a [2] e3 91 [2] ec 8b [2] f2 96 [2] f0 97 [2] eb 91 [2] f7 96 [2] eb b9 }

  condition:
    any of them
}