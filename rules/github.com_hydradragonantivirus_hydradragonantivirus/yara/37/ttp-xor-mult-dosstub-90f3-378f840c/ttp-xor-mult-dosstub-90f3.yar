rule TTP_XOR_MULT_DOSStub_90f3 {
  strings:
    $key_90f3 = { c4 9b [2] b0 83 [2] f7 81 [2] b0 90 [2] fe 9c [2] f2 96 [2] e5 9d [2] fe d3 [2] c3 }

  condition:
    any of them
}