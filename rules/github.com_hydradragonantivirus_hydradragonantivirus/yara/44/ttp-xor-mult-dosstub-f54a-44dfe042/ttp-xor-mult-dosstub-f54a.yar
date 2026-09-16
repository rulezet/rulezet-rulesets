rule TTP_XOR_MULT_DOSStub_f54a {
  strings:
    $key_f54a = { a1 22 [2] d5 3a [2] 92 38 [2] d5 29 [2] 9b 25 [2] 97 2f [2] 80 24 [2] 9b 6a [2] a6 }

  condition:
    any of them
}