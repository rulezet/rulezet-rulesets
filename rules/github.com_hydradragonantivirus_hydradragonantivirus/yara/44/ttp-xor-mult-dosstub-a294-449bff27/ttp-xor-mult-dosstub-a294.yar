rule TTP_XOR_MULT_DOSStub_a294 {
  strings:
    $key_a294 = { f6 fc [2] 82 e4 [2] c5 e6 [2] 82 f7 [2] cc fb [2] c0 f1 [2] d7 fa [2] cc b4 [2] f1 }

  condition:
    any of them
}