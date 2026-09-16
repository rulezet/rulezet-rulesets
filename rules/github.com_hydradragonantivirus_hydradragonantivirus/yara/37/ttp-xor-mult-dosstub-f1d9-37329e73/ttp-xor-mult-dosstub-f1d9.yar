rule TTP_XOR_MULT_DOSStub_f1d9 {
  strings:
    $key_f1d9 = { a5 b1 [2] d1 a9 [2] 96 ab [2] d1 ba [2] 9f b6 [2] 93 bc [2] 84 b7 [2] 9f f9 [2] a2 }

  condition:
    any of them
}