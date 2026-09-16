rule TTP_XOR_MULT_DOSStub_434a {
  strings:
    $key_434a = { 17 22 [2] 63 3a [2] 24 38 [2] 63 29 [2] 2d 25 [2] 21 2f [2] 36 24 [2] 2d 6a [2] 10 }

  condition:
    any of them
}