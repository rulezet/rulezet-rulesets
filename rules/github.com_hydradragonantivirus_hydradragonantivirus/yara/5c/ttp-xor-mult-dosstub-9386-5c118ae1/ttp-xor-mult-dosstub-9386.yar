rule TTP_XOR_MULT_DOSStub_9386 {
  strings:
    $key_9386 = { c7 ee [2] b3 f6 [2] f4 f4 [2] b3 e5 [2] fd e9 [2] f1 e3 [2] e6 e8 [2] fd a6 [2] c0 }

  condition:
    any of them
}