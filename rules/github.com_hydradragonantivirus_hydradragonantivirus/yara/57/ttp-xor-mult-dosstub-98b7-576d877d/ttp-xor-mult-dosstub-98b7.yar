rule TTP_XOR_MULT_DOSStub_98b7 {
  strings:
    $key_98b7 = { cc df [2] b8 c7 [2] ff c5 [2] b8 d4 [2] f6 d8 [2] fa d2 [2] ed d9 [2] f6 97 [2] cb }

  condition:
    any of them
}