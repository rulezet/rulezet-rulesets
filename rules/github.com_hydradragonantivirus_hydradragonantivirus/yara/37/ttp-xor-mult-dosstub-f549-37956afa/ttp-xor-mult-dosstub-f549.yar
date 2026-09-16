rule TTP_XOR_MULT_DOSStub_f549 {
  strings:
    $key_f549 = { a1 21 [2] d5 39 [2] 92 3b [2] d5 2a [2] 9b 26 [2] 97 2c [2] 80 27 [2] 9b 69 [2] a6 }

  condition:
    any of them
}