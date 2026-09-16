rule TTP_XOR_QUAD_CurrentVersionRun_9434 {
  strings:
    $key_9434 = { c7 5b [2] e3 55 [2] c8 79 [2] e6 5b [2] f2 40 [2] fd 5a [2] e3 47 [2] e1 46 [2] fa 40 [2] e6 47 [2] fa 68 }

  condition:
    any of them
}