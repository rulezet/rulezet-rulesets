rule TTP_XOR_MULT_DOSStub_777a {
  strings:
    $key_777a = { 23 12 [2] 57 0a [2] 10 08 [2] 57 19 [2] 19 15 [2] 15 1f [2] 02 14 [2] 19 5a [2] 24 }

  condition:
    any of them
}