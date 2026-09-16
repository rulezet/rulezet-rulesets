rule TTP_XOR_MULT_DOSStub_b7c6 {
  strings:
    $key_b7c6 = { e3 ae [2] 97 b6 [2] d0 b4 [2] 97 a5 [2] d9 a9 [2] d5 a3 [2] c2 a8 [2] d9 e6 [2] e4 }

  condition:
    any of them
}