rule TTP_XOR_QUAD_CurrentVersionRun_91c6 {
  strings:
    $key_91c6 = { c2 a9 [2] e6 a7 [2] cd 8b [2] e3 a9 [2] f7 b2 [2] f8 a8 [2] e6 b5 [2] e4 b4 [2] ff b2 [2] e3 b5 [2] ff 9a }

  condition:
    any of them
}