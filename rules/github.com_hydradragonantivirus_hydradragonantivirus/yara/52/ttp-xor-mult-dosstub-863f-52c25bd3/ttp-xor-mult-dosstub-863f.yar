rule TTP_XOR_MULT_DOSStub_863f {
  strings:
    $key_863f = { d2 57 [2] a6 4f [2] e1 4d [2] a6 5c [2] e8 50 [2] e4 5a [2] f3 51 [2] e8 1f [2] d5 }

  condition:
    any of them
}