rule TTP_XOR_MULT_DOSStub_f095 {
  strings:
    $key_f095 = { a4 fd [2] d0 e5 [2] 97 e7 [2] d0 f6 [2] 9e fa [2] 92 f0 [2] 85 fb [2] 9e b5 [2] a3 }

  condition:
    any of them
}