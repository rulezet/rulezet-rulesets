rule TTP_XOR_MULT_DOSStub_57d1 {
  strings:
    $key_57d1 = { 03 b9 [2] 77 a1 [2] 30 a3 [2] 77 b2 [2] 39 be [2] 35 b4 [2] 22 bf [2] 39 f1 [2] 04 }

  condition:
    any of them
}