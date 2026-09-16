rule TTP_XOR_MULT_DOSStub_f4c8 {
  strings:
    $key_f4c8 = { a0 a0 [2] d4 b8 [2] 93 ba [2] d4 ab [2] 9a a7 [2] 96 ad [2] 81 a6 [2] 9a e8 [2] a7 }

  condition:
    any of them
}