rule TTP_XOR_MULT_DOSStub_7472 {
  strings:
    $key_7472 = { 20 1a [2] 54 02 [2] 13 00 [2] 54 11 [2] 1a 1d [2] 16 17 [2] 01 1c [2] 1a 52 [2] 27 }

  condition:
    any of them
}