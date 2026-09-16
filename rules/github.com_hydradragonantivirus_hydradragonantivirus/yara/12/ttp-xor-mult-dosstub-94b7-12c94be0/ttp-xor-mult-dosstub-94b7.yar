rule TTP_XOR_MULT_DOSStub_94b7 {
  strings:
    $key_94b7 = { c0 df [2] b4 c7 [2] f3 c5 [2] b4 d4 [2] fa d8 [2] f6 d2 [2] e1 d9 [2] fa 97 [2] c7 }

  condition:
    any of them
}