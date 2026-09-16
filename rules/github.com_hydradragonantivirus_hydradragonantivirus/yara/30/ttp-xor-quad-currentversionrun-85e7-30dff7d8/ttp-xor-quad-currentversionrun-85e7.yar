rule TTP_XOR_QUAD_CurrentVersionRun_85e7 {
  strings:
    $key_85e7 = { d6 88 [2] f2 86 [2] d9 aa [2] f7 88 [2] e3 93 [2] ec 89 [2] f2 94 [2] f0 95 [2] eb 93 [2] f7 94 [2] eb bb }

  condition:
    any of them
}