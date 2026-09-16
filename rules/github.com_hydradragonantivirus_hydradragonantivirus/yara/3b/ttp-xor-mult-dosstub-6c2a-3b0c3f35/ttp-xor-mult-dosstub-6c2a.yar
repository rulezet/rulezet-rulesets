rule TTP_XOR_MULT_DOSStub_6c2a {
  strings:
    $key_6c2a = { 38 42 [2] 4c 5a [2] 0b 58 [2] 4c 49 [2] 02 45 [2] 0e 4f [2] 19 44 [2] 02 0a [2] 3f }

  condition:
    any of them
}