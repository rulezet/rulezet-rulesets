rule TTP_XOR_MULT_DOSStub_074a {
  strings:
    $key_074a = { 53 22 [2] 27 3a [2] 60 38 [2] 27 29 [2] 69 25 [2] 65 2f [2] 72 24 [2] 69 6a [2] 54 }

  condition:
    any of them
}