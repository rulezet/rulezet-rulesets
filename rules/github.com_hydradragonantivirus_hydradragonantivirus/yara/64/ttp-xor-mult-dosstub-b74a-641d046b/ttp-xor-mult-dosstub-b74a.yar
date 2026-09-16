rule TTP_XOR_MULT_DOSStub_b74a {
  strings:
    $key_b74a = { e3 22 [2] 97 3a [2] d0 38 [2] 97 29 [2] d9 25 [2] d5 2f [2] c2 24 [2] d9 6a [2] e4 }

  condition:
    any of them
}