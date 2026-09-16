rule TTP_XOR_MULT_DOSStub_594a {
  strings:
    $key_594a = { 0d 22 [2] 79 3a [2] 3e 38 [2] 79 29 [2] 37 25 [2] 3b 2f [2] 2c 24 [2] 37 6a [2] 0a }

  condition:
    any of them
}