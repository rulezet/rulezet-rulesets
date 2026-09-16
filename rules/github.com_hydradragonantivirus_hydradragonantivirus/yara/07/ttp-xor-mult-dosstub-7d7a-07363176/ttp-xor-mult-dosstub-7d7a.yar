rule TTP_XOR_MULT_DOSStub_7d7a {
  strings:
    $key_7d7a = { 29 12 [2] 5d 0a [2] 1a 08 [2] 5d 19 [2] 13 15 [2] 1f 1f [2] 08 14 [2] 13 5a [2] 2e }

  condition:
    any of them
}