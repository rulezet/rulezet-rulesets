rule TTP_XOR_MULT_DOSStub_4a1a {
  strings:
    $key_4a1a = { 1e 72 [2] 6a 6a [2] 2d 68 [2] 6a 79 [2] 24 75 [2] 28 7f [2] 3f 74 [2] 24 3a [2] 19 }

  condition:
    any of them
}