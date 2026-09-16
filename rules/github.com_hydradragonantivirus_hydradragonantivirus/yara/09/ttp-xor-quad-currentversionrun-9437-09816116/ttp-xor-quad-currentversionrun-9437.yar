rule TTP_XOR_QUAD_CurrentVersionRun_9437 {
  strings:
    $key_9437 = { c7 58 [2] e3 56 [2] c8 7a [2] e6 58 [2] f2 43 [2] fd 59 [2] e3 44 [2] e1 45 [2] fa 43 [2] e6 44 [2] fa 6b }

  condition:
    any of them
}