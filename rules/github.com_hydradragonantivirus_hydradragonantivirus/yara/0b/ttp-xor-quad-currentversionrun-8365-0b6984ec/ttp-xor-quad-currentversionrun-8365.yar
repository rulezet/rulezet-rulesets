rule TTP_XOR_QUAD_CurrentVersionRun_8365 {
  strings:
    $key_8365 = { d0 0a [2] f4 04 [2] df 28 [2] f1 0a [2] e5 11 [2] ea 0b [2] f4 16 [2] f6 17 [2] ed 11 [2] f1 16 [2] ed 39 }

  condition:
    any of them
}