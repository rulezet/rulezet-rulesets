rule TTP_XOR_MULT_DOSStub_6c0a {
  strings:
    $key_6c0a = { 38 62 [2] 4c 7a [2] 0b 78 [2] 4c 69 [2] 02 65 [2] 0e 6f [2] 19 64 [2] 02 2a [2] 3f }

  condition:
    any of them
}