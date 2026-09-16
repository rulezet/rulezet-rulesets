rule TTP_XOR_MULT_DOSStub_3a4a {
  strings:
    $key_3a4a = { 6e 22 [2] 1a 3a [2] 5d 38 [2] 1a 29 [2] 54 25 [2] 58 2f [2] 4f 24 [2] 54 6a [2] 69 }

  condition:
    any of them
}