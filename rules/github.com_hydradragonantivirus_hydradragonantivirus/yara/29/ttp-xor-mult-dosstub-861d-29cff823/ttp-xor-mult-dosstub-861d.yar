rule TTP_XOR_MULT_DOSStub_861d {
  strings:
    $key_861d = { d2 75 [2] a6 6d [2] e1 6f [2] a6 7e [2] e8 72 [2] e4 78 [2] f3 73 [2] e8 3d [2] d5 }

  condition:
    any of them
}