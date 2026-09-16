rule TTP_XOR_MULT_DOSStub_7c2a {
  strings:
    $key_7c2a = { 28 42 [2] 5c 5a [2] 1b 58 [2] 5c 49 [2] 12 45 [2] 1e 4f [2] 09 44 [2] 12 0a [2] 2f }

  condition:
    any of them
}