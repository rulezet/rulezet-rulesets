rule TTP_XOR_MULT_DOSStub_f78b {
  strings:
    $key_f78b = { a3 e3 [2] d7 fb [2] 90 f9 [2] d7 e8 [2] 99 e4 [2] 95 ee [2] 82 e5 [2] 99 ab [2] a4 }

  condition:
    any of them
}