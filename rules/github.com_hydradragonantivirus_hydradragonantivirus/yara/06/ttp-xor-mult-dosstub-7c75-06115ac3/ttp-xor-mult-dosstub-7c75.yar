rule TTP_XOR_MULT_DOSStub_7c75 {
  strings:
    $key_7c75 = { 28 1d [2] 5c 05 [2] 1b 07 [2] 5c 16 [2] 12 1a [2] 1e 10 [2] 09 1b [2] 12 55 [2] 2f }

  condition:
    any of them
}