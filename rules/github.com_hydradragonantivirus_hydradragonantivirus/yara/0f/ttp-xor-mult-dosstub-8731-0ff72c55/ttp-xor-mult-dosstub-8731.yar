rule TTP_XOR_MULT_DOSStub_8731 {
  strings:
    $key_8731 = { d3 59 [2] a7 41 [2] e0 43 [2] a7 52 [2] e9 5e [2] e5 54 [2] f2 5f [2] e9 11 [2] d4 }

  condition:
    any of them
}