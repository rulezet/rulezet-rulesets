rule TTP_XOR_MULT_DOSStub_374a {
  strings:
    $key_374a = { 63 22 [2] 17 3a [2] 50 38 [2] 17 29 [2] 59 25 [2] 55 2f [2] 42 24 [2] 59 6a [2] 64 }

  condition:
    any of them
}