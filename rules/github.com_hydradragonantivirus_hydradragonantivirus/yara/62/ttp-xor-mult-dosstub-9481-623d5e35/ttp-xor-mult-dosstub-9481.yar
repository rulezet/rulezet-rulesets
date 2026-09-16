rule TTP_XOR_MULT_DOSStub_9481 {
  strings:
    $key_9481 = { c0 e9 [2] b4 f1 [2] f3 f3 [2] b4 e2 [2] fa ee [2] f6 e4 [2] e1 ef [2] fa a1 [2] c7 }

  condition:
    any of them
}