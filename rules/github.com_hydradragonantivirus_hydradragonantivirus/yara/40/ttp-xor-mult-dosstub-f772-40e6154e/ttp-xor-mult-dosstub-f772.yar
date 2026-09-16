rule TTP_XOR_MULT_DOSStub_f772 {
  strings:
    $key_f772 = { a3 1a [2] d7 02 [2] 90 00 [2] d7 11 [2] 99 1d [2] 95 17 [2] 82 1c [2] 99 52 [2] a4 }

  condition:
    any of them
}