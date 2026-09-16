rule TTP_XOR_MULT_DOSStub_4b4a {
  strings:
    $key_4b4a = { 1f 22 [2] 6b 3a [2] 2c 38 [2] 6b 29 [2] 25 25 [2] 29 2f [2] 3e 24 [2] 25 6a [2] 18 }

  condition:
    any of them
}