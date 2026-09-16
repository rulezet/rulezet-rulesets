rule TTP_XOR_MULT_DOSStub_2172 {
  strings:
    $key_2172 = { 75 1a [2] 01 02 [2] 46 00 [2] 01 11 [2] 4f 1d [2] 43 17 [2] 54 1c [2] 4f 52 [2] 72 }

  condition:
    any of them
}