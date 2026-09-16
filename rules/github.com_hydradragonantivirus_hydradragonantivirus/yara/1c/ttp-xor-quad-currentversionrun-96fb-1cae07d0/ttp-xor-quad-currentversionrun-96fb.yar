rule TTP_XOR_QUAD_CurrentVersionRun_96fb {
  strings:
    $key_96fb = { c5 94 [2] e1 9a [2] ca b6 [2] e4 94 [2] f0 8f [2] ff 95 [2] e1 88 [2] e3 89 [2] f8 8f [2] e4 88 [2] f8 a7 }

  condition:
    any of them
}