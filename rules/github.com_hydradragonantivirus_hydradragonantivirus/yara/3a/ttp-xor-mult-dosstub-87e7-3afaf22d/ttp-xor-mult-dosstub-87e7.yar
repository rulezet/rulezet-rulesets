rule TTP_XOR_MULT_DOSStub_87e7 {
  strings:
    $key_87e7 = { d3 8f [2] a7 97 [2] e0 95 [2] a7 84 [2] e9 88 [2] e5 82 [2] f2 89 [2] e9 c7 [2] d4 }

  condition:
    any of them
}