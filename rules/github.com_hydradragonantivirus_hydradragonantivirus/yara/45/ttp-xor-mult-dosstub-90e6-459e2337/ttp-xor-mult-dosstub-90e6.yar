rule TTP_XOR_MULT_DOSStub_90e6 {
  strings:
    $key_90e6 = { c4 8e [2] b0 96 [2] f7 94 [2] b0 85 [2] fe 89 [2] f2 83 [2] e5 88 [2] fe c6 [2] c3 }

  condition:
    any of them
}