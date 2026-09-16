rule TTP_XOR_MULT_DOSStub_90f1 {
  strings:
    $key_90f1 = { c4 99 [2] b0 81 [2] f7 83 [2] b0 92 [2] fe 9e [2] f2 94 [2] e5 9f [2] fe d1 [2] c3 }

  condition:
    any of them
}