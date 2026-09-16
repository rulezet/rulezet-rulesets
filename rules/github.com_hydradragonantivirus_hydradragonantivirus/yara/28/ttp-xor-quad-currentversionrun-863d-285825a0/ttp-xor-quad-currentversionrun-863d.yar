rule TTP_XOR_QUAD_CurrentVersionRun_863d {
  strings:
    $key_863d = { d5 52 [2] f1 5c [2] da 70 [2] f4 52 [2] e0 49 [2] ef 53 [2] f1 4e [2] f3 4f [2] e8 49 [2] f4 4e [2] e8 61 }

  condition:
    any of them
}