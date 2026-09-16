rule TTP_XOR_MULT_DOSStub_874e {
  strings:
    $key_874e = { d3 26 [2] a7 3e [2] e0 3c [2] a7 2d [2] e9 21 [2] e5 2b [2] f2 20 [2] e9 6e [2] d4 }

  condition:
    any of them
}