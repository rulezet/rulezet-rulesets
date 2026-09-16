rule TTP_XOR_MULT_DOSStub_5b4a {
  strings:
    $key_5b4a = { 0f 22 [2] 7b 3a [2] 3c 38 [2] 7b 29 [2] 35 25 [2] 39 2f [2] 2e 24 [2] 35 6a [2] 08 }

  condition:
    any of them
}