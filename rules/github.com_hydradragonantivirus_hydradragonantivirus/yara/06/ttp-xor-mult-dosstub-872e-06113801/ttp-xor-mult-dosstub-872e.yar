rule TTP_XOR_MULT_DOSStub_872e {
  strings:
    $key_872e = { d3 46 [2] a7 5e [2] e0 5c [2] a7 4d [2] e9 41 [2] e5 4b [2] f2 40 [2] e9 0e [2] d4 }

  condition:
    any of them
}