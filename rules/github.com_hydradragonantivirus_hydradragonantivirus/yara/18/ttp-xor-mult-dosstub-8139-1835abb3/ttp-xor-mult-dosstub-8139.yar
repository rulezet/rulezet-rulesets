rule TTP_XOR_MULT_DOSStub_8139 {
  strings:
    $key_8139 = { d5 51 [2] a1 49 [2] e6 4b [2] a1 5a [2] ef 56 [2] e3 5c [2] f4 57 [2] ef 19 [2] d2 }

  condition:
    any of them
}