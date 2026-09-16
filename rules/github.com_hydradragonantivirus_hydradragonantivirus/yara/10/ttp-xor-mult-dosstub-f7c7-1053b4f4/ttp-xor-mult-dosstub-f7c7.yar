rule TTP_XOR_MULT_DOSStub_f7c7 {
  strings:
    $key_f7c7 = { a3 af [2] d7 b7 [2] 90 b5 [2] d7 a4 [2] 99 a8 [2] 95 a2 [2] 82 a9 [2] 99 e7 [2] a4 }

  condition:
    any of them
}