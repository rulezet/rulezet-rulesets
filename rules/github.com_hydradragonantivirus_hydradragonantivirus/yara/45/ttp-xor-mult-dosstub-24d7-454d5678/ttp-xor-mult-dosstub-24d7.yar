rule TTP_XOR_MULT_DOSStub_24d7 {
  strings:
    $key_24d7 = { 70 bf [2] 04 a7 [2] 43 a5 [2] 04 b4 [2] 4a b8 [2] 46 b2 [2] 51 b9 [2] 4a f7 [2] 77 }

  condition:
    any of them
}