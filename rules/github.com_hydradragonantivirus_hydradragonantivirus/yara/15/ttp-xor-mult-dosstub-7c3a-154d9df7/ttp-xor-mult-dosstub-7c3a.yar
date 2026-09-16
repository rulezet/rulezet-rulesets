rule TTP_XOR_MULT_DOSStub_7c3a {
  strings:
    $key_7c3a = { 28 52 [2] 5c 4a [2] 1b 48 [2] 5c 59 [2] 12 55 [2] 1e 5f [2] 09 54 [2] 12 1a [2] 2f }

  condition:
    any of them
}