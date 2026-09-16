rule TTP_XOR_MULT_DOSStub_0a72 {
  strings:
    $key_0a72 = { 5e 1a [2] 2a 02 [2] 6d 00 [2] 2a 11 [2] 64 1d [2] 68 17 [2] 7f 1c [2] 64 52 [2] 59 }

  condition:
    any of them
}