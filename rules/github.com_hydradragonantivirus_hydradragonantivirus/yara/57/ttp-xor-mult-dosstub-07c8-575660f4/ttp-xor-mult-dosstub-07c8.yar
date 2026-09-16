rule TTP_XOR_MULT_DOSStub_07c8 {
  strings:
    $key_07c8 = { 53 a0 [2] 27 b8 [2] 60 ba [2] 27 ab [2] 69 a7 [2] 65 ad [2] 72 a6 [2] 69 e8 [2] 54 }

  condition:
    any of them
}