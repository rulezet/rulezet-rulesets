rule TTP_XOR_MULT_DOSStub_771a {
  strings:
    $key_771a = { 23 72 [2] 57 6a [2] 10 68 [2] 57 79 [2] 19 75 [2] 15 7f [2] 02 74 [2] 19 3a [2] 24 }

  condition:
    any of them
}