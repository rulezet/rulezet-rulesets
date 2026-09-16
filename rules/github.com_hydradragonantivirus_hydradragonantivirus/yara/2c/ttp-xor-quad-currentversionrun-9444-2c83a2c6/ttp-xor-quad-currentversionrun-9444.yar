rule TTP_XOR_QUAD_CurrentVersionRun_9444 {
  strings:
    $key_9444 = { c7 2b [2] e3 25 [2] c8 09 [2] e6 2b [2] f2 30 [2] fd 2a [2] e3 37 [2] e1 36 [2] fa 30 [2] e6 37 [2] fa 18 }

  condition:
    any of them
}