rule TTP_XOR_MULT_DOSStub_9586 {
  strings:
    $key_9586 = { c1 ee [2] b5 f6 [2] f2 f4 [2] b5 e5 [2] fb e9 [2] f7 e3 [2] e0 e8 [2] fb a6 [2] c6 }

  condition:
    any of them
}