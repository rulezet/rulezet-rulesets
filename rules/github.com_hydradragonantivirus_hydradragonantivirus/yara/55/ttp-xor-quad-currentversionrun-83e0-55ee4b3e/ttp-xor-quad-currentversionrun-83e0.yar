rule TTP_XOR_QUAD_CurrentVersionRun_83e0 {
  strings:
    $key_83e0 = { d0 8f [2] f4 81 [2] df ad [2] f1 8f [2] e5 94 [2] ea 8e [2] f4 93 [2] f6 92 [2] ed 94 [2] f1 93 [2] ed bc }

  condition:
    any of them
}