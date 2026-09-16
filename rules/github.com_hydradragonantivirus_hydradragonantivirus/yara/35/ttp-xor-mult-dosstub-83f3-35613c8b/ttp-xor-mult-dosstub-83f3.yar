rule TTP_XOR_MULT_DOSStub_83f3 {
  strings:
    $key_83f3 = { d7 9b [2] a3 83 [2] e4 81 [2] a3 90 [2] ed 9c [2] e1 96 [2] f6 9d [2] ed d3 [2] d0 }

  condition:
    any of them
}