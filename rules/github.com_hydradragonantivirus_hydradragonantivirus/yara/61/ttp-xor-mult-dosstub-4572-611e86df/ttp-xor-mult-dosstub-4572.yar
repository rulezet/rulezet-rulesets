rule TTP_XOR_MULT_DOSStub_4572 {
  strings:
    $key_4572 = { 11 1a [2] 65 02 [2] 22 00 [2] 65 11 [2] 2b 1d [2] 27 17 [2] 30 1c [2] 2b 52 [2] 16 }

  condition:
    any of them
}