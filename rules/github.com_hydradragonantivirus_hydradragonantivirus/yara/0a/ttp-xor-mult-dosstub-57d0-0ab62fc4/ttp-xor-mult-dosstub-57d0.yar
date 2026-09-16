rule TTP_XOR_MULT_DOSStub_57d0 {
  strings:
    $key_57d0 = { 03 b8 [2] 77 a0 [2] 30 a2 [2] 77 b3 [2] 39 bf [2] 35 b5 [2] 22 be [2] 39 f0 [2] 04 }

  condition:
    any of them
}