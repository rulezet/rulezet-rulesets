rule TTP_XOR_MULT_DOSStub_f5a6 {
  strings:
    $key_f5a6 = { a1 ce [2] d5 d6 [2] 92 d4 [2] d5 c5 [2] 9b c9 [2] 97 c3 [2] 80 c8 [2] 9b 86 [2] a6 }

  condition:
    any of them
}