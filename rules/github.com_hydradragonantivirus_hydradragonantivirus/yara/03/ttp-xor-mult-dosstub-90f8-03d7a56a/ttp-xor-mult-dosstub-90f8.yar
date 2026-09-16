rule TTP_XOR_MULT_DOSStub_90f8 {
  strings:
    $key_90f8 = { c4 90 [2] b0 88 [2] f7 8a [2] b0 9b [2] fe 97 [2] f2 9d [2] e5 96 [2] fe d8 [2] c3 }

  condition:
    any of them
}