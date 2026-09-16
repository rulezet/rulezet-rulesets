rule TTP_XOR_MULT_DOSStub_34c8 {
  strings:
    $key_34c8 = { 60 a0 [2] 14 b8 [2] 53 ba [2] 14 ab [2] 5a a7 [2] 56 ad [2] 41 a6 [2] 5a e8 [2] 67 }

  condition:
    any of them
}