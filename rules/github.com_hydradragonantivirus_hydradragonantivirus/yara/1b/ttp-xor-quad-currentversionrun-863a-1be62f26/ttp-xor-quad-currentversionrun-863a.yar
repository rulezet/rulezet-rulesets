rule TTP_XOR_QUAD_CurrentVersionRun_863a {
  strings:
    $key_863a = { d5 55 [2] f1 5b [2] da 77 [2] f4 55 [2] e0 4e [2] ef 54 [2] f1 49 [2] f3 48 [2] e8 4e [2] f4 49 [2] e8 66 }

  condition:
    any of them
}