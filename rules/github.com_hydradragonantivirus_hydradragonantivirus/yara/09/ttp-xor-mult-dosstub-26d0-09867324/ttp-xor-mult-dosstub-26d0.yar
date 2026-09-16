rule TTP_XOR_MULT_DOSStub_26d0 {
  strings:
    $key_26d0 = { 72 b8 [2] 06 a0 [2] 41 a2 [2] 06 b3 [2] 48 bf [2] 44 b5 [2] 53 be [2] 48 f0 [2] 75 }

  condition:
    any of them
}