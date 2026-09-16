rule TTP_XOR_QUAD_CurrentVersionRun_9465 {
  strings:
    $key_9465 = { c7 0a [2] e3 04 [2] c8 28 [2] e6 0a [2] f2 11 [2] fd 0b [2] e3 16 [2] e1 17 [2] fa 11 [2] e6 16 [2] fa 39 }

  condition:
    any of them
}