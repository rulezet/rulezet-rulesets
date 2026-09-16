rule TTP_XOR_MULT_DOSStub_90e2 {
  strings:
    $key_90e2 = { c4 8a [2] b0 92 [2] f7 90 [2] b0 81 [2] fe 8d [2] f2 87 [2] e5 8c [2] fe c2 [2] c3 }

  condition:
    any of them
}