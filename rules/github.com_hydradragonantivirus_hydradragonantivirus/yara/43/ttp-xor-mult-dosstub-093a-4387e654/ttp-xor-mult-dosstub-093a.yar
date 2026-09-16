rule TTP_XOR_MULT_DOSStub_093a {
  strings:
    $key_093a = { 5d 52 [2] 29 4a [2] 6e 48 [2] 29 59 [2] 67 55 [2] 6b 5f [2] 7c 54 [2] 67 1a [2] 5a }

  condition:
    any of them
}