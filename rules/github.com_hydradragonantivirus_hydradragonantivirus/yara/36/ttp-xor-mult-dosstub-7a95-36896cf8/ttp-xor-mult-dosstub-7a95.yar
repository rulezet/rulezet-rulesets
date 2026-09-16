rule TTP_XOR_MULT_DOSStub_7a95 {
  strings:
    $key_7a95 = { 2e fd [2] 5a e5 [2] 1d e7 [2] 5a f6 [2] 14 fa [2] 18 f0 [2] 0f fb [2] 14 b5 [2] 29 }

  condition:
    any of them
}