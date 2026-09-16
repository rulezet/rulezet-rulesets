rule TTP_XOR_QUAD_CurrentVersionRun_83f0 {
  strings:
    $key_83f0 = { d0 9f [2] f4 91 [2] df bd [2] f1 9f [2] e5 84 [2] ea 9e [2] f4 83 [2] f6 82 [2] ed 84 [2] f1 83 [2] ed ac }

  condition:
    any of them
}