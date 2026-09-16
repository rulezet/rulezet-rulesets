rule TTP_XOR_MULT_DOSStub_90e0 {
  strings:
    $key_90e0 = { c4 88 [2] b0 90 [2] f7 92 [2] b0 83 [2] fe 8f [2] f2 85 [2] e5 8e [2] fe c0 [2] c3 }

  condition:
    any of them
}