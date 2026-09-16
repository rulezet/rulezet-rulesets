rule TTP_XOR_MULT_DOSStub_4995 {
  strings:
    $key_4995 = { 1d fd [2] 69 e5 [2] 2e e7 [2] 69 f6 [2] 27 fa [2] 2b f0 [2] 3c fb [2] 27 b5 [2] 1a }

  condition:
    any of them
}