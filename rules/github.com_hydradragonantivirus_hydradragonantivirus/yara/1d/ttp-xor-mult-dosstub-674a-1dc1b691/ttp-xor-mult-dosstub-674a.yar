rule TTP_XOR_MULT_DOSStub_674a {
  strings:
    $key_674a = { 33 22 [2] 47 3a [2] 00 38 [2] 47 29 [2] 09 25 [2] 05 2f [2] 12 24 [2] 09 6a [2] 34 }

  condition:
    any of them
}