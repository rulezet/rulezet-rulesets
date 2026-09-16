rule TTP_XOR_MULT_DOSStub_862e {
  strings:
    $key_862e = { d2 46 [2] a6 5e [2] e1 5c [2] a6 4d [2] e8 41 [2] e4 4b [2] f3 40 [2] e8 0e [2] d5 }

  condition:
    any of them
}