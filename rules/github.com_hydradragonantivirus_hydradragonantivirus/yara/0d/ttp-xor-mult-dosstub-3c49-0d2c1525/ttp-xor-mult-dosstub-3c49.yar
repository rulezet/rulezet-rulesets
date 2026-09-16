rule TTP_XOR_MULT_DOSStub_3c49 {
  strings:
    $key_3c49 = { 68 21 [2] 1c 39 [2] 5b 3b [2] 1c 2a [2] 52 26 [2] 5e 2c [2] 49 27 [2] 52 69 [2] 6f }

  condition:
    any of them
}