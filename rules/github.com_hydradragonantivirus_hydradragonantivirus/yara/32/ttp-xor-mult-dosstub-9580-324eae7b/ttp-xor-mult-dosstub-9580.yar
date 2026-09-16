rule TTP_XOR_MULT_DOSStub_9580 {
  strings:
    $key_9580 = { c1 e8 [2] b5 f0 [2] f2 f2 [2] b5 e3 [2] fb ef [2] f7 e5 [2] e0 ee [2] fb a0 [2] c6 }

  condition:
    any of them
}