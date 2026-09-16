rule TTP_XOR_MULT_DOSStub_6c5a {
  strings:
    $key_6c5a = { 38 32 [2] 4c 2a [2] 0b 28 [2] 4c 39 [2] 02 35 [2] 0e 3f [2] 19 34 [2] 02 7a [2] 3f }

  condition:
    any of them
}