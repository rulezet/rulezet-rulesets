rule TTP_XOR_MULT_DOSStub_0044 {
  strings:
    $key_0044 = { 54 2c [2] 20 34 [2] 67 36 [2] 20 27 [2] 6e 2b [2] 62 21 [2] 75 2a [2] 6e 64 [2] 53 }

  condition:
    any of them
}