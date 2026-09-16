rule TTP_XOR_MULT_DOSStub_abb8 {
  strings:
    $key_abb8 = { ff d0 [2] 8b c8 [2] cc ca [2] 8b db [2] c5 d7 [2] c9 dd [2] de d6 [2] c5 98 [2] f8 }

  condition:
    any of them
}