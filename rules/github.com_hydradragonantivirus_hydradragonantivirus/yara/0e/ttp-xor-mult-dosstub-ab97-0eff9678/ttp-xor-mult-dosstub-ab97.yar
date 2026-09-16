rule TTP_XOR_MULT_DOSStub_ab97 {
  strings:
    $key_ab97 = { ff ff [2] 8b e7 [2] cc e5 [2] 8b f4 [2] c5 f8 [2] c9 f2 [2] de f9 [2] c5 b7 [2] f8 }

  condition:
    any of them
}