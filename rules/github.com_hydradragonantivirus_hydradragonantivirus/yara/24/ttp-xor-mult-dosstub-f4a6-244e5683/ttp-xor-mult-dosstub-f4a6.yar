rule TTP_XOR_MULT_DOSStub_f4a6 {
  strings:
    $key_f4a6 = { a0 ce [2] d4 d6 [2] 93 d4 [2] d4 c5 [2] 9a c9 [2] 96 c3 [2] 81 c8 [2] 9a 86 [2] a7 }

  condition:
    any of them
}