rule TTP_XOR_MULT_DOSStub_471a {
  strings:
    $key_471a = { 13 72 [2] 67 6a [2] 20 68 [2] 67 79 [2] 29 75 [2] 25 7f [2] 32 74 [2] 29 3a [2] 14 }

  condition:
    any of them
}