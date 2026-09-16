rule TTP_XOR_MULT_DOSStub_87f4 {
  strings:
    $key_87f4 = { d3 9c [2] a7 84 [2] e0 86 [2] a7 97 [2] e9 9b [2] e5 91 [2] f2 9a [2] e9 d4 [2] d4 }

  condition:
    any of them
}