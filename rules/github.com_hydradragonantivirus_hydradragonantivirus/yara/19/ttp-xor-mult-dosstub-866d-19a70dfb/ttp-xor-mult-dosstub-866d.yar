rule TTP_XOR_MULT_DOSStub_866d {
  strings:
    $key_866d = { d2 05 [2] a6 1d [2] e1 1f [2] a6 0e [2] e8 02 [2] e4 08 [2] f3 03 [2] e8 4d [2] d5 }

  condition:
    any of them
}