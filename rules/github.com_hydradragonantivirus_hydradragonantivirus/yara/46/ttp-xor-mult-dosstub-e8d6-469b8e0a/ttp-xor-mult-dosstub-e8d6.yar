rule TTP_XOR_MULT_DOSStub_e8d6 {
  strings:
    $key_e8d6 = { bc be [2] c8 a6 [2] 8f a4 [2] c8 b5 [2] 86 b9 [2] 8a b3 [2] 9d b8 [2] 86 f6 [2] bb }

  condition:
    any of them
}