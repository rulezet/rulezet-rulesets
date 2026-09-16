rule TTP_XOR_MULT_DOSStub_1995 {
  strings:
    $key_1995 = { 4d fd [2] 39 e5 [2] 7e e7 [2] 39 f6 [2] 77 fa [2] 7b f0 [2] 6c fb [2] 77 b5 [2] 4a }

  condition:
    any of them
}