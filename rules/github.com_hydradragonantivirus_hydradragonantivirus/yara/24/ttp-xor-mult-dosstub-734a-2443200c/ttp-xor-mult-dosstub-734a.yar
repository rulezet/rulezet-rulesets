rule TTP_XOR_MULT_DOSStub_734a {
  strings:
    $key_734a = { 27 22 [2] 53 3a [2] 14 38 [2] 53 29 [2] 1d 25 [2] 11 2f [2] 06 24 [2] 1d 6a [2] 20 }

  condition:
    any of them
}