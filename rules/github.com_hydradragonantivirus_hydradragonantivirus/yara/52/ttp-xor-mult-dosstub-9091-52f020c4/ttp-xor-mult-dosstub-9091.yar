rule TTP_XOR_MULT_DOSStub_9091 {
  strings:
    $key_9091 = { c4 f9 [2] b0 e1 [2] f7 e3 [2] b0 f2 [2] fe fe [2] f2 f4 [2] e5 ff [2] fe b1 [2] c3 }

  condition:
    any of them
}