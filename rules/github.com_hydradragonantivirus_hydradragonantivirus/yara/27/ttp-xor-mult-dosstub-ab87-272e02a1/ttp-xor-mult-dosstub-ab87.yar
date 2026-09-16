rule TTP_XOR_MULT_DOSStub_ab87 {
  strings:
    $key_ab87 = { ff ef [2] 8b f7 [2] cc f5 [2] 8b e4 [2] c5 e8 [2] c9 e2 [2] de e9 [2] c5 a7 [2] f8 }

  condition:
    any of them
}