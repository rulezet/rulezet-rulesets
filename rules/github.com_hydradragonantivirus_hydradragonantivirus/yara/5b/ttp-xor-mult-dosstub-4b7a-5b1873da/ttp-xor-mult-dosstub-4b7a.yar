rule TTP_XOR_MULT_DOSStub_4b7a {
  strings:
    $key_4b7a = { 1f 12 [2] 6b 0a [2] 2c 08 [2] 6b 19 [2] 25 15 [2] 29 1f [2] 3e 14 [2] 25 5a [2] 18 }

  condition:
    any of them
}