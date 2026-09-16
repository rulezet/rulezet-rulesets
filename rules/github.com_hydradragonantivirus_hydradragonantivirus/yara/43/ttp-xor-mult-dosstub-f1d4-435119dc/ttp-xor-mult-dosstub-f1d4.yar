rule TTP_XOR_MULT_DOSStub_f1d4 {
  strings:
    $key_f1d4 = { a5 bc [2] d1 a4 [2] 96 a6 [2] d1 b7 [2] 9f bb [2] 93 b1 [2] 84 ba [2] 9f f4 [2] a2 }

  condition:
    any of them
}