rule TTP_XOR_QUAD_CurrentVersionRun_94fb {
  strings:
    $key_94fb = { c7 94 [2] e3 9a [2] c8 b6 [2] e6 94 [2] f2 8f [2] fd 95 [2] e3 88 [2] e1 89 [2] fa 8f [2] e6 88 [2] fa a7 }

  condition:
    any of them
}