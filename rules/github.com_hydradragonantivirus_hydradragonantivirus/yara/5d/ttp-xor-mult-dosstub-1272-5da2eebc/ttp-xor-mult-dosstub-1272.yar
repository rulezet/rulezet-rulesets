rule TTP_XOR_MULT_DOSStub_1272 {
  strings:
    $key_1272 = { 46 1a [2] 32 02 [2] 75 00 [2] 32 11 [2] 7c 1d [2] 70 17 [2] 67 1c [2] 7c 52 [2] 41 }

  condition:
    any of them
}