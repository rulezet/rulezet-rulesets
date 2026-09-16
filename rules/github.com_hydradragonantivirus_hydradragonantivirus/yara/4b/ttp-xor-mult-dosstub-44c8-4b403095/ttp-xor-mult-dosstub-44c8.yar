rule TTP_XOR_MULT_DOSStub_44c8 {
  strings:
    $key_44c8 = { 10 a0 [2] 64 b8 [2] 23 ba [2] 64 ab [2] 2a a7 [2] 26 ad [2] 31 a6 [2] 2a e8 [2] 17 }

  condition:
    any of them
}