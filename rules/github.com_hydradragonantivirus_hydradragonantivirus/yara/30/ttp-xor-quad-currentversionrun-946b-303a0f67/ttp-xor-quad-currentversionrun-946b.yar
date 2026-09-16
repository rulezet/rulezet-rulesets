rule TTP_XOR_QUAD_CurrentVersionRun_946b {
  strings:
    $key_946b = { c7 04 [2] e3 0a [2] c8 26 [2] e6 04 [2] f2 1f [2] fd 05 [2] e3 18 [2] e1 19 [2] fa 1f [2] e6 18 [2] fa 37 }

  condition:
    any of them
}