rule TTP_XOR_MULT_DOSStub_866f {
  strings:
    $key_866f = { d2 07 [2] a6 1f [2] e1 1d [2] a6 0c [2] e8 00 [2] e4 0a [2] f3 01 [2] e8 4f [2] d5 }

  condition:
    any of them
}