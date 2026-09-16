rule TTP_XOR_MULT_DOSStub_6c1a {
  strings:
    $key_6c1a = { 38 72 [2] 4c 6a [2] 0b 68 [2] 4c 79 [2] 02 75 [2] 0e 7f [2] 19 74 [2] 02 3a [2] 3f }

  condition:
    any of them
}