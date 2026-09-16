rule TTP_XOR_MULT_DOSStub_a588 {
  strings:
    $key_a588 = { f1 e0 [2] 85 f8 [2] c2 fa [2] 85 eb [2] cb e7 [2] c7 ed [2] d0 e6 [2] cb a8 [2] f6 }

  condition:
    any of them
}