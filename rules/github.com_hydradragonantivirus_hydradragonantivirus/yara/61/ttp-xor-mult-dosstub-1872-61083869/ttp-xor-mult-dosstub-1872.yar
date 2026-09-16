rule TTP_XOR_MULT_DOSStub_1872 {
  strings:
    $key_1872 = { 4c 1a [2] 38 02 [2] 7f 00 [2] 38 11 [2] 76 1d [2] 7a 17 [2] 6d 1c [2] 76 52 [2] 4b }

  condition:
    any of them
}