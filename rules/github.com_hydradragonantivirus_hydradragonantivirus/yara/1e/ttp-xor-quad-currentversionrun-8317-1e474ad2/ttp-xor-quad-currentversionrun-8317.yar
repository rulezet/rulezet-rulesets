rule TTP_XOR_QUAD_CurrentVersionRun_8317 {
  strings:
    $key_8317 = { d0 78 [2] f4 76 [2] df 5a [2] f1 78 [2] e5 63 [2] ea 79 [2] f4 64 [2] f6 65 [2] ed 63 [2] f1 64 [2] ed 4b }

  condition:
    any of them
}