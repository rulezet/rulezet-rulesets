rule TTP_XOR_MULT_DOSStub_763a {
  strings:
    $key_763a = { 22 52 [2] 56 4a [2] 11 48 [2] 56 59 [2] 18 55 [2] 14 5f [2] 03 54 [2] 18 1a [2] 25 }

  condition:
    any of them
}