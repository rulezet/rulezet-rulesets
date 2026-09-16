rule TTP_XOR_MULT_DOSStub_7b4a {
  strings:
    $key_7b4a = { 2f 22 [2] 5b 3a [2] 1c 38 [2] 5b 29 [2] 15 25 [2] 19 2f [2] 0e 24 [2] 15 6a [2] 28 }

  condition:
    any of them
}