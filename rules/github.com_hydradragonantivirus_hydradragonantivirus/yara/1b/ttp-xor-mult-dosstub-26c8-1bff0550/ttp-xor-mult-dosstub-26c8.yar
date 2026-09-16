rule TTP_XOR_MULT_DOSStub_26c8 {
  strings:
    $key_26c8 = { 72 a0 [2] 06 b8 [2] 41 ba [2] 06 ab [2] 48 a7 [2] 44 ad [2] 53 a6 [2] 48 e8 [2] 75 }

  condition:
    any of them
}