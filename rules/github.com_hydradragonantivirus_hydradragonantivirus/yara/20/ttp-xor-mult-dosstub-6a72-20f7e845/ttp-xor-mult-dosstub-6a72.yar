rule TTP_XOR_MULT_DOSStub_6a72 {
  strings:
    $key_6a72 = { 3e 1a [2] 4a 02 [2] 0d 00 [2] 4a 11 [2] 04 1d [2] 08 17 [2] 1f 1c [2] 04 52 [2] 39 }

  condition:
    any of them
}