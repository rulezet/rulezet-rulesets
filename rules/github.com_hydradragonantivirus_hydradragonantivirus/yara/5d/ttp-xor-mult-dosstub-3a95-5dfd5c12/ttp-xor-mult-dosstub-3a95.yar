rule TTP_XOR_MULT_DOSStub_3a95 {
  strings:
    $key_3a95 = { 6e fd [2] 1a e5 [2] 5d e7 [2] 1a f6 [2] 54 fa [2] 58 f0 [2] 4f fb [2] 54 b5 [2] 69 }

  condition:
    any of them
}