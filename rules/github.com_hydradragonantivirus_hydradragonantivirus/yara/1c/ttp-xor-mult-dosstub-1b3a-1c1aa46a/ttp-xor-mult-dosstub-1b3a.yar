rule TTP_XOR_MULT_DOSStub_1b3a {
  strings:
    $key_1b3a = { 4f 52 [2] 3b 4a [2] 7c 48 [2] 3b 59 [2] 75 55 [2] 79 5f [2] 6e 54 [2] 75 1a [2] 48 }

  condition:
    any of them
}