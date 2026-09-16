rule TTP_XOR_MULT_DOSStub_313a {
  strings:
    $key_313a = { 65 52 [2] 11 4a [2] 56 48 [2] 11 59 [2] 5f 55 [2] 53 5f [2] 44 54 [2] 5f 1a [2] 62 }

  condition:
    any of them
}