rule TTP_XOR_QUAD_CurrentVersionRun_83fb {
  strings:
    $key_83fb = { d0 94 [2] f4 9a [2] df b6 [2] f1 94 [2] e5 8f [2] ea 95 [2] f4 88 [2] f6 89 [2] ed 8f [2] f1 88 [2] ed a7 }

  condition:
    any of them
}