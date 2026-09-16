rule TTP_XOR_MULT_DOSStub_78a8 {
  strings:
    $key_78a8 = { 2c c0 [2] 58 d8 [2] 1f da [2] 58 cb [2] 16 c7 [2] 1a cd [2] 0d c6 [2] 16 88 [2] 2b }

  condition:
    any of them
}