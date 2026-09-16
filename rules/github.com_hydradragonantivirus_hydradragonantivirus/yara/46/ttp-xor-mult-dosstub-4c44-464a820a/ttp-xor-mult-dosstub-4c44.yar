rule TTP_XOR_MULT_DOSStub_4c44 {
  strings:
    $key_4c44 = { 18 2c [2] 6c 34 [2] 2b 36 [2] 6c 27 [2] 22 2b [2] 2e 21 [2] 39 2a [2] 22 64 [2] 1f }

  condition:
    any of them
}