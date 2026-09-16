rule TTP_XOR_QUAD_CurrentVersionRun_8337 {
  strings:
    $key_8337 = { d0 58 [2] f4 56 [2] df 7a [2] f1 58 [2] e5 43 [2] ea 59 [2] f4 44 [2] f6 45 [2] ed 43 [2] f1 44 [2] ed 6b }

  condition:
    any of them
}