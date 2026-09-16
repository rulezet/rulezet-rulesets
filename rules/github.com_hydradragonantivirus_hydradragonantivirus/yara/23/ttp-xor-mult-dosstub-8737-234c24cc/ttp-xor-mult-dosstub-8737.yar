rule TTP_XOR_MULT_DOSStub_8737 {
  strings:
    $key_8737 = { d3 5f [2] a7 47 [2] e0 45 [2] a7 54 [2] e9 58 [2] e5 52 [2] f2 59 [2] e9 17 [2] d4 }

  condition:
    any of them
}