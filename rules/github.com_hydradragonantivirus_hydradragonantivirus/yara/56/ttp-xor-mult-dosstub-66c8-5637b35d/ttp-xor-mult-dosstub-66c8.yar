rule TTP_XOR_MULT_DOSStub_66c8 {
  strings:
    $key_66c8 = { 32 a0 [2] 46 b8 [2] 01 ba [2] 46 ab [2] 08 a7 [2] 04 ad [2] 13 a6 [2] 08 e8 [2] 35 }

  condition:
    any of them
}