rule TTP_XOR_MULT_DOSStub_abb7 {
  strings:
    $key_abb7 = { ff df [2] 8b c7 [2] cc c5 [2] 8b d4 [2] c5 d8 [2] c9 d2 [2] de d9 [2] c5 97 [2] f8 }

  condition:
    any of them
}