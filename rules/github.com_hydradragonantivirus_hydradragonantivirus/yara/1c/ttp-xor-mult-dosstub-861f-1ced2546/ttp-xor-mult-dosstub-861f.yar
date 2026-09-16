rule TTP_XOR_MULT_DOSStub_861f {
  strings:
    $key_861f = { d2 77 [2] a6 6f [2] e1 6d [2] a6 7c [2] e8 70 [2] e4 7a [2] f3 71 [2] e8 3f [2] d5 }

  condition:
    any of them
}