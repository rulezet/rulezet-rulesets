rule TTP_XOR_MULT_DOSStub_754a {
  strings:
    $key_754a = { 21 22 [2] 55 3a [2] 12 38 [2] 55 29 [2] 1b 25 [2] 17 2f [2] 00 24 [2] 1b 6a [2] 26 }

  condition:
    any of them
}