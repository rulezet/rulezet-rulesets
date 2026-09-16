rule TTP_XOR_MULT_DOSStub_f562 {
  strings:
    $key_f562 = { a1 0a [2] d5 12 [2] 92 10 [2] d5 01 [2] 9b 0d [2] 97 07 [2] 80 0c [2] 9b 42 [2] a6 }

  condition:
    any of them
}