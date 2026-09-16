rule TTP_XOR_QUAD_CurrentVersionRun_83f1 {
  strings:
    $key_83f1 = { d0 9e [2] f4 90 [2] df bc [2] f1 9e [2] e5 85 [2] ea 9f [2] f4 82 [2] f6 83 [2] ed 85 [2] f1 82 [2] ed ad }

  condition:
    any of them
}