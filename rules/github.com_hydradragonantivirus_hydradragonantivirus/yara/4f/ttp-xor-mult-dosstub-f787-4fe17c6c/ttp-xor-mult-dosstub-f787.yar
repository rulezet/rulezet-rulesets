rule TTP_XOR_MULT_DOSStub_f787 {
  strings:
    $key_f787 = { a3 ef [2] d7 f7 [2] 90 f5 [2] d7 e4 [2] 99 e8 [2] 95 e2 [2] 82 e9 [2] 99 a7 [2] a4 }

  condition:
    any of them
}