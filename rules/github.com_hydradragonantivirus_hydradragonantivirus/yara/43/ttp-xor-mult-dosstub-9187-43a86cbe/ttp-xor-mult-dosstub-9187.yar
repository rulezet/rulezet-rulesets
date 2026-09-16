rule TTP_XOR_MULT_DOSStub_9187 {
  strings:
    $key_9187 = { c5 ef [2] b1 f7 [2] f6 f5 [2] b1 e4 [2] ff e8 [2] f3 e2 [2] e4 e9 [2] ff a7 [2] c2 }

  condition:
    any of them
}