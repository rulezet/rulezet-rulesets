rule TTP_XOR_MULT_DOSStub_f6a6 {
  strings:
    $key_f6a6 = { a2 ce [2] d6 d6 [2] 91 d4 [2] d6 c5 [2] 98 c9 [2] 94 c3 [2] 83 c8 [2] 98 86 [2] a5 }

  condition:
    any of them
}