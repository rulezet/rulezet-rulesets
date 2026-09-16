rule TTP_XOR_MULT_DOSStub_3b4a {
  strings:
    $key_3b4a = { 6f 22 [2] 1b 3a [2] 5c 38 [2] 1b 29 [2] 55 25 [2] 59 2f [2] 4e 24 [2] 55 6a [2] 68 }

  condition:
    any of them
}