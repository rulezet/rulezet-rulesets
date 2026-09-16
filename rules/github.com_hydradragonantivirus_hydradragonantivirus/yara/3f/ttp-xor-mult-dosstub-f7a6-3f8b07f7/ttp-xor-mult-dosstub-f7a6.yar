rule TTP_XOR_MULT_DOSStub_f7a6 {
  strings:
    $key_f7a6 = { a3 ce [2] d7 d6 [2] 90 d4 [2] d7 c5 [2] 99 c9 [2] 95 c3 [2] 82 c8 [2] 99 86 [2] a4 }

  condition:
    any of them
}