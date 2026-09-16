rule TTP_XOR_MULT_DOSStub_4a3a {
  strings:
    $key_4a3a = { 1e 52 [2] 6a 4a [2] 2d 48 [2] 6a 59 [2] 24 55 [2] 28 5f [2] 3f 54 [2] 24 1a [2] 19 }

  condition:
    any of them
}