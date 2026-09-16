rule TTP_XOR_QUAD_CurrentVersionRun_9468 {
  strings:
    $key_9468 = { c7 07 [2] e3 09 [2] c8 25 [2] e6 07 [2] f2 1c [2] fd 06 [2] e3 1b [2] e1 1a [2] fa 1c [2] e6 1b [2] fa 34 }

  condition:
    any of them
}