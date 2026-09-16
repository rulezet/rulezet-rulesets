rule TTP_XOR_MULT_DOSStub_87e9 {
  strings:
    $key_87e9 = { d3 81 [2] a7 99 [2] e0 9b [2] a7 8a [2] e9 86 [2] e5 8c [2] f2 87 [2] e9 c9 [2] d4 }

  condition:
    any of them
}