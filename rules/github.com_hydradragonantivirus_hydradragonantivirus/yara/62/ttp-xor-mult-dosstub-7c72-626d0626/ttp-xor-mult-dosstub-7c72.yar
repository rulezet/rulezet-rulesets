rule TTP_XOR_MULT_DOSStub_7c72 {
  strings:
    $key_7c72 = { 28 1a [2] 5c 02 [2] 1b 00 [2] 5c 11 [2] 12 1d [2] 1e 17 [2] 09 1c [2] 12 52 [2] 2f }

  condition:
    any of them
}