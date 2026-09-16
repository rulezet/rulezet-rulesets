rule TTP_XOR_MULT_DOSStub_9087 {
  strings:
    $key_9087 = { c4 ef [2] b0 f7 [2] f7 f5 [2] b0 e4 [2] fe e8 [2] f2 e2 [2] e5 e9 [2] fe a7 [2] c3 }

  condition:
    any of them
}