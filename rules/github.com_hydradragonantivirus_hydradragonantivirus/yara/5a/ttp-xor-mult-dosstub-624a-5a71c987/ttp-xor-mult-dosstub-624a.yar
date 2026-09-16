rule TTP_XOR_MULT_DOSStub_624a {
  strings:
    $key_624a = { 36 22 [2] 42 3a [2] 05 38 [2] 42 29 [2] 0c 25 [2] 00 2f [2] 17 24 [2] 0c 6a [2] 31 }

  condition:
    any of them
}