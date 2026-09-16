rule TTP_XOR_QUAD_CurrentVersionRun_9405 {
  strings:
    $key_9405 = { c7 6a [2] e3 64 [2] c8 48 [2] e6 6a [2] f2 71 [2] fd 6b [2] e3 76 [2] e1 77 [2] fa 71 [2] e6 76 [2] fa 59 }

  condition:
    any of them
}