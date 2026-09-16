rule TTP_XOR_QUAD_CurrentVersionRun_9404 {
  strings:
    $key_9404 = { c7 6b [2] e3 65 [2] c8 49 [2] e6 6b [2] f2 70 [2] fd 6a [2] e3 77 [2] e1 76 [2] fa 70 [2] e6 77 [2] fa 58 }

  condition:
    any of them
}