rule TTP_XOR_MULT_DOSStub_f4ab {
  strings:
    $key_f4ab = { a0 c3 [2] d4 db [2] 93 d9 [2] d4 c8 [2] 9a c4 [2] 96 ce [2] 81 c5 [2] 9a 8b [2] a7 }

  condition:
    any of them
}