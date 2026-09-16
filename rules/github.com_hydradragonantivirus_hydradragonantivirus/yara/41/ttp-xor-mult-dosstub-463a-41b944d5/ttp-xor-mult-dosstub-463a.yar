rule TTP_XOR_MULT_DOSStub_463a {
  strings:
    $key_463a = { 12 52 [2] 66 4a [2] 21 48 [2] 66 59 [2] 28 55 [2] 24 5f [2] 33 54 [2] 28 1a [2] 15 }

  condition:
    any of them
}