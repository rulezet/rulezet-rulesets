rule TTP_XOR_MULT_DOSStub_875c {
  strings:
    $key_875c = { d3 34 [2] a7 2c [2] e0 2e [2] a7 3f [2] e9 33 [2] e5 39 [2] f2 32 [2] e9 7c [2] d4 }

  condition:
    any of them
}