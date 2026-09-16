rule TTP_XOR_MULT_DOSStub_f094 {
  strings:
    $key_f094 = { a4 fc [2] d0 e4 [2] 97 e6 [2] d0 f7 [2] 9e fb [2] 92 f1 [2] 85 fa [2] 9e b4 [2] a3 }

  condition:
    any of them
}