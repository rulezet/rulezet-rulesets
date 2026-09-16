rule TTP_XOR_MULT_DOSStub_f44a {
  strings:
    $key_f44a = { a0 22 [2] d4 3a [2] 93 38 [2] d4 29 [2] 9a 25 [2] 96 2f [2] 81 24 [2] 9a 6a [2] a7 }

  condition:
    any of them
}