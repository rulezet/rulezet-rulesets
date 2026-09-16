rule TTP_XOR_MULT_DOSStub_49fa {
  strings:
    $key_49fa = { 1d 92 [2] 69 8a [2] 2e 88 [2] 69 99 [2] 27 95 [2] 2b 9f [2] 3c 94 [2] 27 da [2] 1a }

  condition:
    any of them
}