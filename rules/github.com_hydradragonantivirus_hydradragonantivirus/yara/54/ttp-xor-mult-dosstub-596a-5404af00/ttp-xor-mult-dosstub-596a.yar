rule TTP_XOR_MULT_DOSStub_596a {
  strings:
    $key_596a = { 0d 02 [2] 79 1a [2] 3e 18 [2] 79 09 [2] 37 05 [2] 3b 0f [2] 2c 04 [2] 37 4a [2] 0a }

  condition:
    any of them
}