rule TTP_XOR_MULT_DOSStub_1972 {
  strings:
    $key_1972 = { 4d 1a [2] 39 02 [2] 7e 00 [2] 39 11 [2] 77 1d [2] 7b 17 [2] 6c 1c [2] 77 52 [2] 4a }

  condition:
    any of them
}