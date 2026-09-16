rule TTP_XOR_MULT_DOSStub_1a72 {
  strings:
    $key_1a72 = { 4e 1a [2] 3a 02 [2] 7d 00 [2] 3a 11 [2] 74 1d [2] 78 17 [2] 6f 1c [2] 74 52 [2] 49 }

  condition:
    any of them
}