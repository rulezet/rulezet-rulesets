rule TTP_XOR_MULT_DOSStub_f7c6 {
  strings:
    $key_f7c6 = { a3 ae [2] d7 b6 [2] 90 b4 [2] d7 a5 [2] 99 a9 [2] 95 a3 [2] 82 a8 [2] 99 e6 [2] a4 }

  condition:
    any of them
}