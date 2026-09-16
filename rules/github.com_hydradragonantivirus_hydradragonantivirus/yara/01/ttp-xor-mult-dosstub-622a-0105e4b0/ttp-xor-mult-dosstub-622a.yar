rule TTP_XOR_MULT_DOSStub_622a {
  strings:
    $key_622a = { 36 42 [2] 42 5a [2] 05 58 [2] 42 49 [2] 0c 45 [2] 00 4f [2] 17 44 [2] 0c 0a [2] 31 }

  condition:
    any of them
}