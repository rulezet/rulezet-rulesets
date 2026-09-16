rule TTP_XOR_MULT_DOSStub_e1d7 {
  strings:
    $key_e1d7 = { b5 bf [2] c1 a7 [2] 86 a5 [2] c1 b4 [2] 8f b8 [2] 83 b2 [2] 94 b9 [2] 8f f7 [2] b2 }

  condition:
    any of them
}