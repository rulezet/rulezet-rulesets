rule TTP_XOR_MULT_DOSStub_3a3a {
  strings:
    $key_3a3a = { 6e 52 [2] 1a 4a [2] 5d 48 [2] 1a 59 [2] 54 55 [2] 58 5f [2] 4f 54 [2] 54 1a [2] 69 }

  condition:
    any of them
}