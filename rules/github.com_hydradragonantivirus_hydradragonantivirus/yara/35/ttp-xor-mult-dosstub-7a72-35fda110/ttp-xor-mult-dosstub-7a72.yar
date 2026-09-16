rule TTP_XOR_MULT_DOSStub_7a72 {
  strings:
    $key_7a72 = { 2e 1a [2] 5a 02 [2] 1d 00 [2] 5a 11 [2] 14 1d [2] 18 17 [2] 0f 1c [2] 14 52 [2] 29 }

  condition:
    any of them
}