rule TTP_XOR_MULT_DOSStub_e686 {
  strings:
    $key_e686 = { b2 ee [2] c6 f6 [2] 81 f4 [2] c6 e5 [2] 88 e9 [2] 84 e3 [2] 93 e8 [2] 88 a6 [2] b5 }

  condition:
    any of them
}