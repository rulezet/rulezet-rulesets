rule TTP_XOR_MULT_DOSStub_8721 {
  strings:
    $key_8721 = { d3 49 [2] a7 51 [2] e0 53 [2] a7 42 [2] e9 4e [2] e5 44 [2] f2 4f [2] e9 01 [2] d4 }

  condition:
    any of them
}