rule TTP_XOR_MULT_DOSStub_4a4a {
  strings:
    $key_4a4a = { 1e 22 [2] 6a 3a [2] 2d 38 [2] 6a 29 [2] 24 25 [2] 28 2f [2] 3f 24 [2] 24 6a [2] 19 }

  condition:
    any of them
}