rule TTP_XOR_MULT_DOSStub_f7f8 {
  strings:
    $key_f7f8 = { a3 90 [2] d7 88 [2] 90 8a [2] d7 9b [2] 99 97 [2] 95 9d [2] 82 96 [2] 99 d8 [2] a4 }

  condition:
    any of them
}