rule TTP_XOR_MULT_DOSStub_07d0 {
  strings:
    $key_07d0 = { 53 b8 [2] 27 a0 [2] 60 a2 [2] 27 b3 [2] 69 bf [2] 65 b5 [2] 72 be [2] 69 f0 [2] 54 }

  condition:
    any of them
}