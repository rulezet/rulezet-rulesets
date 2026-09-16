rule TTP_XOR_QUAD_CurrentVersionRun_9408 {
  strings:
    $key_9408 = { c7 67 [2] e3 69 [2] c8 45 [2] e6 67 [2] f2 7c [2] fd 66 [2] e3 7b [2] e1 7a [2] fa 7c [2] e6 7b [2] fa 54 }

  condition:
    any of them
}