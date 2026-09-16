rule TTP_XOR_MULT_DOSStub_701a {
  strings:
    $key_701a = { 24 72 [2] 50 6a [2] 17 68 [2] 50 79 [2] 1e 75 [2] 12 7f [2] 05 74 [2] 1e 3a [2] 23 }

  condition:
    any of them
}