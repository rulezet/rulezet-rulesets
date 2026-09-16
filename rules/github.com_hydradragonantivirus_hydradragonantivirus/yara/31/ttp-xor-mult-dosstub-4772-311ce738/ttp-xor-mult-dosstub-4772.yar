rule TTP_XOR_MULT_DOSStub_4772 {
  strings:
    $key_4772 = { 13 1a [2] 67 02 [2] 20 00 [2] 67 11 [2] 29 1d [2] 25 17 [2] 32 1c [2] 29 52 [2] 14 }

  condition:
    any of them
}