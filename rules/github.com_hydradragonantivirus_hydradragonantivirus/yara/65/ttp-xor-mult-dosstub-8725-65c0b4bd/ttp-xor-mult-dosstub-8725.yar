rule TTP_XOR_MULT_DOSStub_8725 {
  strings:
    $key_8725 = { d3 4d [2] a7 55 [2] e0 57 [2] a7 46 [2] e9 4a [2] e5 40 [2] f2 4b [2] e9 05 [2] d4 }

  condition:
    any of them
}