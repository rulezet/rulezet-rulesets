rule TTP_XOR_MULT_DOSStub_5644 {
  strings:
    $key_5644 = { 02 2c [2] 76 34 [2] 31 36 [2] 76 27 [2] 38 2b [2] 34 21 [2] 23 2a [2] 38 64 [2] 05 }

  condition:
    any of them
}