rule TTP_XOR_MULT_DOSStub_85f3 {
  strings:
    $key_85f3 = { d1 9b [2] a5 83 [2] e2 81 [2] a5 90 [2] eb 9c [2] e7 96 [2] f0 9d [2] eb d3 [2] d6 }

  condition:
    any of them
}