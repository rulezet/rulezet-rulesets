rule TTP_XOR_MULT_DOSStub_f481 {
  strings:
    $key_f481 = { a0 e9 [2] d4 f1 [2] 93 f3 [2] d4 e2 [2] 9a ee [2] 96 e4 [2] 81 ef [2] 9a a1 [2] a7 }

  condition:
    any of them
}