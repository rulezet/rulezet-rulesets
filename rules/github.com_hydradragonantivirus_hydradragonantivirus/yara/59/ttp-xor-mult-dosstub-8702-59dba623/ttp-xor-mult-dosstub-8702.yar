rule TTP_XOR_MULT_DOSStub_8702 {
  strings:
    $key_8702 = { d3 6a [2] a7 72 [2] e0 70 [2] a7 61 [2] e9 6d [2] e5 67 [2] f2 6c [2] e9 22 [2] d4 }

  condition:
    any of them
}