rule TTP_XOR_MULT_DOSStub_3c4a {
  strings:
    $key_3c4a = { 68 22 [2] 1c 3a [2] 5b 38 [2] 1c 29 [2] 52 25 [2] 5e 2f [2] 49 24 [2] 52 6a [2] 6f }

  condition:
    any of them
}