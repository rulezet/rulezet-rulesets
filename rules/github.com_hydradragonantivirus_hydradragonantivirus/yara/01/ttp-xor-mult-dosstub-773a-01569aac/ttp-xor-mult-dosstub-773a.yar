rule TTP_XOR_MULT_DOSStub_773a {
  strings:
    $key_773a = { 23 52 [2] 57 4a [2] 10 48 [2] 57 59 [2] 19 55 [2] 15 5f [2] 02 54 [2] 19 1a [2] 24 }

  condition:
    any of them
}