rule TTP_XOR_MULT_DOSStub_394a {
  strings:
    $key_394a = { 6d 22 [2] 19 3a [2] 5e 38 [2] 19 29 [2] 57 25 [2] 5b 2f [2] 4c 24 [2] 57 6a [2] 6a }

  condition:
    any of them
}