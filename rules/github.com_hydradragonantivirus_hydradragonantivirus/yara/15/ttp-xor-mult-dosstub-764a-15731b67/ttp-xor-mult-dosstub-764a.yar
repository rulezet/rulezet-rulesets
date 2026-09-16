rule TTP_XOR_MULT_DOSStub_764a {
  strings:
    $key_764a = { 22 22 [2] 56 3a [2] 11 38 [2] 56 29 [2] 18 25 [2] 14 2f [2] 03 24 [2] 18 6a [2] 25 }

  condition:
    any of them
}