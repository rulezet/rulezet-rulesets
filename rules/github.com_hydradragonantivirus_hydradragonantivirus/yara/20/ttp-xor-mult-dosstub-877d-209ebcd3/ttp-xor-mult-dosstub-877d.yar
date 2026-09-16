rule TTP_XOR_MULT_DOSStub_877d {
  strings:
    $key_877d = { d3 15 [2] a7 0d [2] e0 0f [2] a7 1e [2] e9 12 [2] e5 18 [2] f2 13 [2] e9 5d [2] d4 }

  condition:
    any of them
}