rule TTP_XOR_MULT_DOSStub_02c8 {
  strings:
    $key_02c8 = { 56 a0 [2] 22 b8 [2] 65 ba [2] 22 ab [2] 6c a7 [2] 60 ad [2] 77 a6 [2] 6c e8 [2] 51 }

  condition:
    any of them
}