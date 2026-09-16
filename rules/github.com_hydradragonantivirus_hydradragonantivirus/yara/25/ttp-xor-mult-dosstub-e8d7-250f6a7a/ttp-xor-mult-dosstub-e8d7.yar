rule TTP_XOR_MULT_DOSStub_e8d7 {
  strings:
    $key_e8d7 = { bc bf [2] c8 a7 [2] 8f a5 [2] c8 b4 [2] 86 b8 [2] 8a b2 [2] 9d b9 [2] 86 f7 [2] bb }

  condition:
    any of them
}