rule TTP_XOR_MULT_DOSStub_ab95 {
  strings:
    $key_ab95 = { ff fd [2] 8b e5 [2] cc e7 [2] 8b f6 [2] c5 fa [2] c9 f0 [2] de fb [2] c5 b5 [2] f8 }

  condition:
    any of them
}