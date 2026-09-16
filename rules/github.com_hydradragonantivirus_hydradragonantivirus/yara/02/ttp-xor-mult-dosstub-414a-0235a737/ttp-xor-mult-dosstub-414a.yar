rule TTP_XOR_MULT_DOSStub_414a {
  strings:
    $key_414a = { 15 22 [2] 61 3a [2] 26 38 [2] 61 29 [2] 2f 25 [2] 23 2f [2] 34 24 [2] 2f 6a [2] 12 }

  condition:
    any of them
}