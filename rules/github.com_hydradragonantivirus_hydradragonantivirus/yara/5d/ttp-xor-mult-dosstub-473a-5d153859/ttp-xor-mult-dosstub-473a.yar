rule TTP_XOR_MULT_DOSStub_473a {
  strings:
    $key_473a = { 13 52 [2] 67 4a [2] 20 48 [2] 67 59 [2] 29 55 [2] 25 5f [2] 32 54 [2] 29 1a [2] 14 }

  condition:
    any of them
}