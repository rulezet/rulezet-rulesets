rule TTP_XOR_MULT_DOSStub_87f9 {
  strings:
    $key_87f9 = { d3 91 [2] a7 89 [2] e0 8b [2] a7 9a [2] e9 96 [2] e5 9c [2] f2 97 [2] e9 d9 [2] d4 }

  condition:
    any of them
}