rule TTP_XOR_MULT_DOSStub_874a {
  strings:
    $key_874a = { d3 22 [2] a7 3a [2] e0 38 [2] a7 29 [2] e9 25 [2] e5 2f [2] f2 24 [2] e9 6a [2] d4 }

  condition:
    any of them
}