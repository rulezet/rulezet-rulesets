rule TTP_XOR_MULT_DOSStub_2e4a {
  strings:
    $key_2e4a = { 7a 22 [2] 0e 3a [2] 49 38 [2] 0e 29 [2] 40 25 [2] 4c 2f [2] 5b 24 [2] 40 6a [2] 7d }

  condition:
    any of them
}