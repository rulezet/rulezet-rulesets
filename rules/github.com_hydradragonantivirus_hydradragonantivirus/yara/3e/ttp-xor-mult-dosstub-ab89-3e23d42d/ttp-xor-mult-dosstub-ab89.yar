rule TTP_XOR_MULT_DOSStub_ab89 {
  strings:
    $key_ab89 = { ff e1 [2] 8b f9 [2] cc fb [2] 8b ea [2] c5 e6 [2] c9 ec [2] de e7 [2] c5 a9 [2] f8 }

  condition:
    any of them
}