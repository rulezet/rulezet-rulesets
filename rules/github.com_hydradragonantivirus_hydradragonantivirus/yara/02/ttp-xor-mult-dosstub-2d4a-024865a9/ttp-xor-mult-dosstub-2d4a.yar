rule TTP_XOR_MULT_DOSStub_2d4a {
  strings:
    $key_2d4a = { 79 22 [2] 0d 3a [2] 4a 38 [2] 0d 29 [2] 43 25 [2] 4f 2f [2] 58 24 [2] 43 6a [2] 7e }

  condition:
    any of them
}