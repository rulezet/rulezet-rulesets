rule TTP_XOR_MULT_DOSStub_16d7 {
  strings:
    $key_16d7 = { 42 bf [2] 36 a7 [2] 71 a5 [2] 36 b4 [2] 78 b8 [2] 74 b2 [2] 63 b9 [2] 78 f7 [2] 45 }

  condition:
    any of them
}