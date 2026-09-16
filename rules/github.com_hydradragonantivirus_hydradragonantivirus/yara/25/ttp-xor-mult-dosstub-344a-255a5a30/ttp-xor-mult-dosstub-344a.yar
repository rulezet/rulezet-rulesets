rule TTP_XOR_MULT_DOSStub_344a {
  strings:
    $key_344a = { 60 22 [2] 14 3a [2] 53 38 [2] 14 29 [2] 5a 25 [2] 56 2f [2] 41 24 [2] 5a 6a [2] 67 }

  condition:
    any of them
}