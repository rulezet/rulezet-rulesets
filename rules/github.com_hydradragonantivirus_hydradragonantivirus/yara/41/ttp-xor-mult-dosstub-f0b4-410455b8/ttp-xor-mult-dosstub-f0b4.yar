rule TTP_XOR_MULT_DOSStub_f0b4 {
  strings:
    $key_f0b4 = { a4 dc [2] d0 c4 [2] 97 c6 [2] d0 d7 [2] 9e db [2] 92 d1 [2] 85 da [2] 9e 94 [2] a3 }

  condition:
    any of them
}