rule TTP_XOR_QUAD_CurrentVersionRun_84f9 {
  strings:
    $key_84f9 = { d7 96 [2] f3 98 [2] d8 b4 [2] f6 96 [2] e2 8d [2] ed 97 [2] f3 8a [2] f1 8b [2] ea 8d [2] f6 8a [2] ea a5 }

  condition:
    any of them
}