rule TTP_XOR_MULT_DOSStub_5572 {
  strings:
    $key_5572 = { 01 1a [2] 75 02 [2] 32 00 [2] 75 11 [2] 3b 1d [2] 37 17 [2] 20 1c [2] 3b 52 [2] 06 }

  condition:
    any of them
}