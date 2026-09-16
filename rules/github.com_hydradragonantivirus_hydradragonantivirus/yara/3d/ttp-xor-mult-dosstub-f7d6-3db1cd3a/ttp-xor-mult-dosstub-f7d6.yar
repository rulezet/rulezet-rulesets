rule TTP_XOR_MULT_DOSStub_f7d6 {
  strings:
    $key_f7d6 = { a3 be [2] d7 a6 [2] 90 a4 [2] d7 b5 [2] 99 b9 [2] 95 b3 [2] 82 b8 [2] 99 f6 [2] a4 }

  condition:
    any of them
}