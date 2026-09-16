rule TTP_XOR_MULT_DOSStub_f51a {
  strings:
    $key_f51a = { a1 72 [2] d5 6a [2] 92 68 [2] d5 79 [2] 9b 75 [2] 97 7f [2] 80 74 [2] 9b 3a [2] a6 }

  condition:
    any of them
}