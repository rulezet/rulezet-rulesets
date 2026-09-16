rule TTP_XOR_MULT_DOSStub_404a {
  strings:
    $key_404a = { 14 22 [2] 60 3a [2] 27 38 [2] 60 29 [2] 2e 25 [2] 22 2f [2] 35 24 [2] 2e 6a [2] 13 }

  condition:
    any of them
}