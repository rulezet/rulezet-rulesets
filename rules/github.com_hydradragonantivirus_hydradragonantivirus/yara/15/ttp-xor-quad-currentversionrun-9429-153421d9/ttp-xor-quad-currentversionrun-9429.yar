rule TTP_XOR_QUAD_CurrentVersionRun_9429 {
  strings:
    $key_9429 = { c7 46 [2] e3 48 [2] c8 64 [2] e6 46 [2] f2 5d [2] fd 47 [2] e3 5a [2] e1 5b [2] fa 5d [2] e6 5a [2] fa 75 }

  condition:
    any of them
}