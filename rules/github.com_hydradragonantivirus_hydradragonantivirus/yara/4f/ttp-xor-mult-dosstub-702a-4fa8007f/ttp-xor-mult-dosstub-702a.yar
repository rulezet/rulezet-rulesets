rule TTP_XOR_MULT_DOSStub_702a {
  strings:
    $key_702a = { 24 42 [2] 50 5a [2] 17 58 [2] 50 49 [2] 1e 45 [2] 12 4f [2] 05 44 [2] 1e 0a [2] 23 }

  condition:
    any of them
}