rule TTP_XOR_MULT_DOSStub_1b7a {
  strings:
    $key_1b7a = { 4f 12 [2] 3b 0a [2] 7c 08 [2] 3b 19 [2] 75 15 [2] 79 1f [2] 6e 14 [2] 75 5a [2] 48 }

  condition:
    any of them
}