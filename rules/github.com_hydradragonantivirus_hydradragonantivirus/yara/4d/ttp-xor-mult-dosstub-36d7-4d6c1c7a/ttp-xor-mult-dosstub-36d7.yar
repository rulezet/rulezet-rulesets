rule TTP_XOR_MULT_DOSStub_36d7 {
  strings:
    $key_36d7 = { 62 bf [2] 16 a7 [2] 51 a5 [2] 16 b4 [2] 58 b8 [2] 54 b2 [2] 43 b9 [2] 58 f7 [2] 65 }

  condition:
    any of them
}