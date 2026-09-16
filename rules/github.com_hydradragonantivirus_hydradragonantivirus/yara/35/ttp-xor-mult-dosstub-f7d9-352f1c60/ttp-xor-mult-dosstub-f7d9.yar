rule TTP_XOR_MULT_DOSStub_f7d9 {
  strings:
    $key_f7d9 = { a3 b1 [2] d7 a9 [2] 90 ab [2] d7 ba [2] 99 b6 [2] 95 bc [2] 82 b7 [2] 99 f9 [2] a4 }

  condition:
    any of them
}