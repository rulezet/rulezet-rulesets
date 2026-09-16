rule TTP_XOR_MULT_DOSStub_f749 {
  strings:
    $key_f749 = { a3 21 [2] d7 39 [2] 90 3b [2] d7 2a [2] 99 26 [2] 95 2c [2] 82 27 [2] 99 69 [2] a4 }

  condition:
    any of them
}