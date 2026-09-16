rule TTP_XOR_MULT_DOSStub_2995 {
  strings:
    $key_2995 = { 7d fd [2] 09 e5 [2] 4e e7 [2] 09 f6 [2] 47 fa [2] 4b f0 [2] 5c fb [2] 47 b5 [2] 7a }

  condition:
    any of them
}