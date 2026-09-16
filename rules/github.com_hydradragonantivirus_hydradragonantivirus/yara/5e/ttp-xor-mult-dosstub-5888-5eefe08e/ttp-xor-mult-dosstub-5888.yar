rule TTP_XOR_MULT_DOSStub_5888 {
  strings:
    $key_5888 = { 0c e0 [2] 78 f8 [2] 3f fa [2] 78 eb [2] 36 e7 [2] 3a ed [2] 2d e6 [2] 36 a8 [2] 0b }

  condition:
    any of them
}