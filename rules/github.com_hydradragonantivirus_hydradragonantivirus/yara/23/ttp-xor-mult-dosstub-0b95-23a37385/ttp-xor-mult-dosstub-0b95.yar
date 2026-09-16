rule TTP_XOR_MULT_DOSStub_0b95 {
  strings:
    $key_0b95 = { 5f fd [2] 2b e5 [2] 6c e7 [2] 2b f6 [2] 65 fa [2] 69 f0 [2] 7e fb [2] 65 b5 [2] 58 }

  condition:
    any of them
}