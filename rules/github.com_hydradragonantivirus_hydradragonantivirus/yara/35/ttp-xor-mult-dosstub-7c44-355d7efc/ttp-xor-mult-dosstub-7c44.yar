rule TTP_XOR_MULT_DOSStub_7c44 {
  strings:
    $key_7c44 = { 28 2c [2] 5c 34 [2] 1b 36 [2] 5c 27 [2] 12 2b [2] 1e 21 [2] 09 2a [2] 12 64 [2] 2f }

  condition:
    any of them
}