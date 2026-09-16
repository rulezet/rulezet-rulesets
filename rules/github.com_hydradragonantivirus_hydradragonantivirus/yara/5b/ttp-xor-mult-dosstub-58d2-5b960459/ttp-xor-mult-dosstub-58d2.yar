rule TTP_XOR_MULT_DOSStub_58d2 {
  strings:
    $key_58d2 = { 0c ba [2] 78 a2 [2] 3f a0 [2] 78 b1 [2] 36 bd [2] 3a b7 [2] 2d bc [2] 36 f2 [2] 0b }

  condition:
    any of them
}