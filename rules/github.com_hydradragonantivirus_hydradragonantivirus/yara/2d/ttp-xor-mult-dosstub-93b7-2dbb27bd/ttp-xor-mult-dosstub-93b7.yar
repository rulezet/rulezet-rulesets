rule TTP_XOR_MULT_DOSStub_93b7 {
  strings:
    $key_93b7 = { c7 df [2] b3 c7 [2] f4 c5 [2] b3 d4 [2] fd d8 [2] f1 d2 [2] e6 d9 [2] fd 97 [2] c0 }

  condition:
    any of them
}