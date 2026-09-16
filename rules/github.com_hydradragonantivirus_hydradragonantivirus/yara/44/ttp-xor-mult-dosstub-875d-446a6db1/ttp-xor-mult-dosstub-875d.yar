rule TTP_XOR_MULT_DOSStub_875d {
  strings:
    $key_875d = { d3 35 [2] a7 2d [2] e0 2f [2] a7 3e [2] e9 32 [2] e5 38 [2] f2 33 [2] e9 7d [2] d4 }

  condition:
    any of them
}