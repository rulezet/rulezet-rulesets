rule TTP_XOR_MULT_DOSStub_72c8 {
  strings:
    $key_72c8 = { 26 a0 [2] 52 b8 [2] 15 ba [2] 52 ab [2] 1c a7 [2] 10 ad [2] 07 a6 [2] 1c e8 [2] 21 }

  condition:
    any of them
}