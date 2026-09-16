rule TTP_XOR_MULT_DOSStub_62c8 {
  strings:
    $key_62c8 = { 36 a0 [2] 42 b8 [2] 05 ba [2] 42 ab [2] 0c a7 [2] 00 ad [2] 17 a6 [2] 0c e8 [2] 31 }

  condition:
    any of them
}