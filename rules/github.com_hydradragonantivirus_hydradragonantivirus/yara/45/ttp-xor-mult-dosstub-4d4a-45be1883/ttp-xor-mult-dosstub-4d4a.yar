rule TTP_XOR_MULT_DOSStub_4d4a {
  strings:
    $key_4d4a = { 19 22 [2] 6d 3a [2] 2a 38 [2] 6d 29 [2] 23 25 [2] 2f 2f [2] 38 24 [2] 23 6a [2] 1e }

  condition:
    any of them
}