rule TTP_XOR_MULT_DOSStub_0095 {
  strings:
    $key_0095 = { 54 fd [2] 20 e5 [2] 67 e7 [2] 20 f6 [2] 6e fa [2] 62 f0 [2] 75 fb [2] 6e b5 [2] 53 }

  condition:
    any of them
}