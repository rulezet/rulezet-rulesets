rule TTP_XOR_QUAD_CurrentVersionRun_8424 {
  strings:
    $key_8424 = { d7 4b [2] f3 45 [2] d8 69 [2] f6 4b [2] e2 50 [2] ed 4a [2] f3 57 [2] f1 56 [2] ea 50 [2] f6 57 [2] ea 78 }

  condition:
    any of them
}