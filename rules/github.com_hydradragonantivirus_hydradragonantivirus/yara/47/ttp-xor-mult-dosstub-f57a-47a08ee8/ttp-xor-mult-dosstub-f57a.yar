rule TTP_XOR_MULT_DOSStub_f57a {
  strings:
    $key_f57a = { a1 12 [2] d5 0a [2] 92 08 [2] d5 19 [2] 9b 15 [2] 97 1f [2] 80 14 [2] 9b 5a [2] a6 }

  condition:
    any of them
}