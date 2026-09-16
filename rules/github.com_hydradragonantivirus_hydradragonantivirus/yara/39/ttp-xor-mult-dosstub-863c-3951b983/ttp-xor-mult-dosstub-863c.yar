rule TTP_XOR_MULT_DOSStub_863c {
  strings:
    $key_863c = { d2 54 [2] a6 4c [2] e1 4e [2] a6 5f [2] e8 53 [2] e4 59 [2] f3 52 [2] e8 1c [2] d5 }

  condition:
    any of them
}