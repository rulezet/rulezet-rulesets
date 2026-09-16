rule TTP_XOR_MULT_DOSStub_47d0 {
  strings:
    $key_47d0 = { 13 b8 [2] 67 a0 [2] 20 a2 [2] 67 b3 [2] 29 bf [2] 25 b5 [2] 32 be [2] 29 f0 [2] 14 }

  condition:
    any of them
}