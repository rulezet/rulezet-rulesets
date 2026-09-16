rule TTP_XOR_MULT_DOSStub_8bbb {
  strings:
    $key_8bbb = { df d3 [2] ab cb [2] ec c9 [2] ab d8 [2] e5 d4 [2] e9 de [2] fe d5 [2] e5 9b [2] d8 }

  condition:
    any of them
}