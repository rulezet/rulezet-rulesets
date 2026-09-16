rule TTP_XOR_MULT_DOSStub_4a7a {
  strings:
    $key_4a7a = { 1e 12 [2] 6a 0a [2] 2d 08 [2] 6a 19 [2] 24 15 [2] 28 1f [2] 3f 14 [2] 24 5a [2] 19 }

  condition:
    any of them
}