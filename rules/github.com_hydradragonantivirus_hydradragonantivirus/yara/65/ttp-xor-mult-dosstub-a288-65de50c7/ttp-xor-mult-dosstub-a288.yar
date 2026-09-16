rule TTP_XOR_MULT_DOSStub_a288 {
  strings:
    $key_a288 = { f6 e0 [2] 82 f8 [2] c5 fa [2] 82 eb [2] cc e7 [2] c0 ed [2] d7 e6 [2] cc a8 [2] f1 }

  condition:
    any of them
}