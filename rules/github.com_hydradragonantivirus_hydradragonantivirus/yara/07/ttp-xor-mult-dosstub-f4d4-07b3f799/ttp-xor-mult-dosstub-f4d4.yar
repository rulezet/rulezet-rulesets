rule TTP_XOR_MULT_DOSStub_f4d4 {
  strings:
    $key_f4d4 = { a0 bc [2] d4 a4 [2] 93 a6 [2] d4 b7 [2] 9a bb [2] 96 b1 [2] 81 ba [2] 9a f4 [2] a7 }

  condition:
    any of them
}