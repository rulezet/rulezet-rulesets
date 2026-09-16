rule TTP_XOR_MULT_DOSStub_f032 {
  strings:
    $key_f032 = { a4 5a [2] d0 42 [2] 97 40 [2] d0 51 [2] 9e 5d [2] 92 57 [2] 85 5c [2] 9e 12 [2] a3 }

  condition:
    any of them
}