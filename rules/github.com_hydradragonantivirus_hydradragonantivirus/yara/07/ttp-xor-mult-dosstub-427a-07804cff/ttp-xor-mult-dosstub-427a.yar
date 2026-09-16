rule TTP_XOR_MULT_DOSStub_427a {
  strings:
    $key_427a = { 16 12 [2] 62 0a [2] 25 08 [2] 62 19 [2] 2c 15 [2] 20 1f [2] 37 14 [2] 2c 5a [2] 11 }

  condition:
    any of them
}