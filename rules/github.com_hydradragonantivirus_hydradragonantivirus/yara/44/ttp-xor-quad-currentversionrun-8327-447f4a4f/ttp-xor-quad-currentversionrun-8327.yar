rule TTP_XOR_QUAD_CurrentVersionRun_8327 {
  strings:
    $key_8327 = { d0 48 [2] f4 46 [2] df 6a [2] f1 48 [2] e5 53 [2] ea 49 [2] f4 54 [2] f6 55 [2] ed 53 [2] f1 54 [2] ed 7b }

  condition:
    any of them
}