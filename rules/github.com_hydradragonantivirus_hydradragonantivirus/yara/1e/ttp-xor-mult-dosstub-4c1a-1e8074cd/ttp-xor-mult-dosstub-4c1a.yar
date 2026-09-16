rule TTP_XOR_MULT_DOSStub_4c1a {
  strings:
    $key_4c1a = { 18 72 [2] 6c 6a [2] 2b 68 [2] 6c 79 [2] 22 75 [2] 2e 7f [2] 39 74 [2] 22 3a [2] 1f }

  condition:
    any of them
}