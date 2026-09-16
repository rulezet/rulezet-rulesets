rule TTP_XOR_MULT_DOSStub_f532 {
  strings:
    $key_f532 = { a1 5a [2] d5 42 [2] 92 40 [2] d5 51 [2] 9b 5d [2] 97 57 [2] 80 5c [2] 9b 12 [2] a6 }

  condition:
    any of them
}