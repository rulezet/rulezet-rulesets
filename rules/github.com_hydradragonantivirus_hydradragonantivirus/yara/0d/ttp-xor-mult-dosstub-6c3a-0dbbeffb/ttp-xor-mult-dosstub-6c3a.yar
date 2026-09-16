rule TTP_XOR_MULT_DOSStub_6c3a {
  strings:
    $key_6c3a = { 38 52 [2] 4c 4a [2] 0b 48 [2] 4c 59 [2] 02 55 [2] 0e 5f [2] 19 54 [2] 02 1a [2] 3f }

  condition:
    any of them
}