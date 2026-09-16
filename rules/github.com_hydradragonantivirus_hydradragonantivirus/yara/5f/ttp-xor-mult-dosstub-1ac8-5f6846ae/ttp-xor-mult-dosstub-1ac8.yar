rule TTP_XOR_MULT_DOSStub_1ac8 {
  strings:
    $key_1ac8 = { 4e a0 [2] 3a b8 [2] 7d ba [2] 3a ab [2] 74 a7 [2] 78 ad [2] 6f a6 [2] 74 e8 [2] 49 }

  condition:
    any of them
}