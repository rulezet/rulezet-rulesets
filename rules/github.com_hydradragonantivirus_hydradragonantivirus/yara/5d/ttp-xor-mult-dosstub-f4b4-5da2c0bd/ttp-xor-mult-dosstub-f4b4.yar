rule TTP_XOR_MULT_DOSStub_f4b4 {
  strings:
    $key_f4b4 = { a0 dc [2] d4 c4 [2] 93 c6 [2] d4 d7 [2] 9a db [2] 96 d1 [2] 81 da [2] 9a 94 [2] a7 }

  condition:
    any of them
}