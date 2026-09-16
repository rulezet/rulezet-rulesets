rule TTP_XOR_MULT_DOSStub_001a {
  strings:
    $key_001a = { 54 72 [2] 20 6a [2] 67 68 [2] 20 79 [2] 6e 75 [2] 62 7f [2] 75 74 [2] 6e 3a [2] 53 }

  condition:
    any of them
}