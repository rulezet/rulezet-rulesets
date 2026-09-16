rule TTP_XOR_MULT_DOSStub_06d7 {
  strings:
    $key_06d7 = { 52 bf [2] 26 a7 [2] 61 a5 [2] 26 b4 [2] 68 b8 [2] 64 b2 [2] 73 b9 [2] 68 f7 [2] 55 }

  condition:
    any of them
}