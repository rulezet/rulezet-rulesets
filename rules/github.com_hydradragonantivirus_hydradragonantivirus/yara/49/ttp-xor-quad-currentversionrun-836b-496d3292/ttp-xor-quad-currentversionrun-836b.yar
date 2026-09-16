rule TTP_XOR_QUAD_CurrentVersionRun_836b {
  strings:
    $key_836b = { d0 04 [2] f4 0a [2] df 26 [2] f1 04 [2] e5 1f [2] ea 05 [2] f4 18 [2] f6 19 [2] ed 1f [2] f1 18 [2] ed 37 }

  condition:
    any of them
}