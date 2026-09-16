rule TTP_XOR_MULT_DOSStub_57d6 {
  strings:
    $key_57d6 = { 03 be [2] 77 a6 [2] 30 a4 [2] 77 b5 [2] 39 b9 [2] 35 b3 [2] 22 b8 [2] 39 f6 [2] 04 }

  condition:
    any of them
}