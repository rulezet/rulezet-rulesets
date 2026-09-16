rule TTP_XOR_MULT_DOSStub_f2f8 {
  strings:
    $key_f2f8 = { a6 90 [2] d2 88 [2] 95 8a [2] d2 9b [2] 9c 97 [2] 90 9d [2] 87 96 [2] 9c d8 [2] a1 }

  condition:
    any of them
}