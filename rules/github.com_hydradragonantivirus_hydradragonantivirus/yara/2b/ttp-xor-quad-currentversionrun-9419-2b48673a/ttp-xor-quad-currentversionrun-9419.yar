rule TTP_XOR_QUAD_CurrentVersionRun_9419 {
  strings:
    $key_9419 = { c7 76 [2] e3 78 [2] c8 54 [2] e6 76 [2] f2 6d [2] fd 77 [2] e3 6a [2] e1 6b [2] fa 6d [2] e6 6a [2] fa 45 }

  condition:
    any of them
}