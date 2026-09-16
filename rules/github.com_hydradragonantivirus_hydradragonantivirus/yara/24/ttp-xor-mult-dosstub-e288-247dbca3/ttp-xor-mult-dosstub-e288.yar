rule TTP_XOR_MULT_DOSStub_e288 {
  strings:
    $key_e288 = { b6 e0 [2] c2 f8 [2] 85 fa [2] c2 eb [2] 8c e7 [2] 80 ed [2] 97 e6 [2] 8c a8 [2] b1 }

  condition:
    any of them
}