rule TTP_XOR_MULT_DOSStub_5b7a {
  strings:
    $key_5b7a = { 0f 12 [2] 7b 0a [2] 3c 08 [2] 7b 19 [2] 35 15 [2] 39 1f [2] 2e 14 [2] 35 5a [2] 08 }

  condition:
    any of them
}