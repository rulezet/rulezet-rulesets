rule TTP_XOR_QUAD_CurrentVersionRun_85fb {
  strings:
    $key_85fb = { d6 94 [2] f2 9a [2] d9 b6 [2] f7 94 [2] e3 8f [2] ec 95 [2] f2 88 [2] f0 89 [2] eb 8f [2] f7 88 [2] eb a7 }

  condition:
    any of them
}