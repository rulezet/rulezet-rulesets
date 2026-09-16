rule TTP_XOR_MULT_DOSStub_e6c7 {
  strings:
    $key_e6c7 = { b2 af [2] c6 b7 [2] 81 b5 [2] c6 a4 [2] 88 a8 [2] 84 a2 [2] 93 a9 [2] 88 e7 [2] b5 }

  condition:
    any of them
}