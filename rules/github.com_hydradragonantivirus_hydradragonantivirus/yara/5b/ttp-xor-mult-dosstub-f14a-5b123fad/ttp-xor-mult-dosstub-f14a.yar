rule TTP_XOR_MULT_DOSStub_f14a {
  strings:
    $key_f14a = { a5 22 [2] d1 3a [2] 96 38 [2] d1 29 [2] 9f 25 [2] 93 2f [2] 84 24 [2] 9f 6a [2] a2 }

  condition:
    any of them
}