rule TTP_XOR_MULT_DOSStub_87f3 {
  strings:
    $key_87f3 = { d3 9b [2] a7 83 [2] e0 81 [2] a7 90 [2] e9 9c [2] e5 96 [2] f2 9d [2] e9 d3 [2] d4 }

  condition:
    any of them
}