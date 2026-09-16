rule TTP_XOR_MULT_DOSStub_863d {
  strings:
    $key_863d = { d2 55 [2] a6 4d [2] e1 4f [2] a6 5e [2] e8 52 [2] e4 58 [2] f3 53 [2] e8 1d [2] d5 }

  condition:
    any of them
}