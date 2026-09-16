rule TTP_XOR_MULT_DOSStub_9097 {
  strings:
    $key_9097 = { c4 ff [2] b0 e7 [2] f7 e5 [2] b0 f4 [2] fe f8 [2] f2 f2 [2] e5 f9 [2] fe b7 [2] c3 }

  condition:
    any of them
}