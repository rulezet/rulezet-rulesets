rule TTP_XOR_MULT_DOSStub_9186 {
  strings:
    $key_9186 = { c5 ee [2] b1 f6 [2] f6 f4 [2] b1 e5 [2] ff e9 [2] f3 e3 [2] e4 e8 [2] ff a6 [2] c2 }

  condition:
    any of them
}