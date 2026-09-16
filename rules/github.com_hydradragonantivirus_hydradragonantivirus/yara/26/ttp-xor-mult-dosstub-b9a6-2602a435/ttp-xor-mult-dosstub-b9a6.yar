rule TTP_XOR_MULT_DOSStub_b9a6 {
  strings:
    $key_b9a6 = { ed ce [2] 99 d6 [2] de d4 [2] 99 c5 [2] d7 c9 [2] db c3 [2] cc c8 [2] d7 86 [2] ea }

  condition:
    any of them
}