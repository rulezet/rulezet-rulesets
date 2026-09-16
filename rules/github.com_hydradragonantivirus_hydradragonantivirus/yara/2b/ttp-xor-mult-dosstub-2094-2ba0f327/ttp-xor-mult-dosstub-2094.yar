rule TTP_XOR_MULT_DOSStub_2094 {
  strings:
    $key_2094 = { 74 fc [2] 00 e4 [2] 47 e6 [2] 00 f7 [2] 4e fb [2] 42 f1 [2] 55 fa [2] 4e b4 [2] 73 }

  condition:
    any of them
}