rule TTP_XOR_MULT_DOSStub_90f7 {
  strings:
    $key_90f7 = { c4 9f [2] b0 87 [2] f7 85 [2] b0 94 [2] fe 98 [2] f2 92 [2] e5 99 [2] fe d7 [2] c3 }

  condition:
    any of them
}