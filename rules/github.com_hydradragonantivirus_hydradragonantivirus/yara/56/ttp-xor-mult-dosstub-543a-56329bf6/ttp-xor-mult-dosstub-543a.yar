rule TTP_XOR_MULT_DOSStub_543a {
  strings:
    $key_543a = { 00 52 [2] 74 4a [2] 33 48 [2] 74 59 [2] 3a 55 [2] 36 5f [2] 21 54 [2] 3a 1a [2] 07 }

  condition:
    any of them
}