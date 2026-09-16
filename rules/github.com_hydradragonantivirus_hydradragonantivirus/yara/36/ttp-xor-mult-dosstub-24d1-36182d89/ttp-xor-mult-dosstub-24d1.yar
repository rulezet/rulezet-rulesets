rule TTP_XOR_MULT_DOSStub_24d1 {
  strings:
    $key_24d1 = { 70 b9 [2] 04 a1 [2] 43 a3 [2] 04 b2 [2] 4a be [2] 46 b4 [2] 51 bf [2] 4a f1 [2] 77 }

  condition:
    any of them
}