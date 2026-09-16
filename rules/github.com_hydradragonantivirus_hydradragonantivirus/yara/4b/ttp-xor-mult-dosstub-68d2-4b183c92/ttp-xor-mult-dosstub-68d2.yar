rule TTP_XOR_MULT_DOSStub_68d2 {
  strings:
    $key_68d2 = { 3c ba [2] 48 a2 [2] 0f a0 [2] 48 b1 [2] 06 bd [2] 0a b7 [2] 1d bc [2] 06 f2 [2] 3b }

  condition:
    any of them
}