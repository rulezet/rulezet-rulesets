rule TTP_XOR_MULT_DOSStub_5072 {
  strings:
    $key_5072 = { 04 1a [2] 70 02 [2] 37 00 [2] 70 11 [2] 3e 1d [2] 32 17 [2] 25 1c [2] 3e 52 [2] 03 }

  condition:
    any of them
}