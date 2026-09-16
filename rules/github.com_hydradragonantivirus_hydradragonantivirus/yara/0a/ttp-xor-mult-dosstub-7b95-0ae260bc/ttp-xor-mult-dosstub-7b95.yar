rule TTP_XOR_MULT_DOSStub_7b95 {
  strings:
    $key_7b95 = { 2f fd [2] 5b e5 [2] 1c e7 [2] 5b f6 [2] 15 fa [2] 19 f0 [2] 0e fb [2] 15 b5 [2] 28 }

  condition:
    any of them
}