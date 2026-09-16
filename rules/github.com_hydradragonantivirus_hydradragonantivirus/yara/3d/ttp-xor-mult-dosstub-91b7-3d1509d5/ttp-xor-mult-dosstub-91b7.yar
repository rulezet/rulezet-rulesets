rule TTP_XOR_MULT_DOSStub_91b7 {
  strings:
    $key_91b7 = { c5 df [2] b1 c7 [2] f6 c5 [2] b1 d4 [2] ff d8 [2] f3 d2 [2] e4 d9 [2] ff 97 [2] c2 }

  condition:
    any of them
}