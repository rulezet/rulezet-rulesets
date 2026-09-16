rule TTP_XOR_MULT_DOSStub_044a {
  strings:
    $key_044a = { 50 22 [2] 24 3a [2] 63 38 [2] 24 29 [2] 6a 25 [2] 66 2f [2] 71 24 [2] 6a 6a [2] 57 }

  condition:
    any of them
}