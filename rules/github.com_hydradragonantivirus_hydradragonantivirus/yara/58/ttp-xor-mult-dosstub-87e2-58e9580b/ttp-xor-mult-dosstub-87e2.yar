rule TTP_XOR_MULT_DOSStub_87e2 {
  strings:
    $key_87e2 = { d3 8a [2] a7 92 [2] e0 90 [2] a7 81 [2] e9 8d [2] e5 87 [2] f2 8c [2] e9 c2 [2] d4 }

  condition:
    any of them
}