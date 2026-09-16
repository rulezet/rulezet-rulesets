rule TTP_XOR_MULT_DOSStub_4972 {
  strings:
    $key_4972 = { 1d 1a [2] 69 02 [2] 2e 00 [2] 69 11 [2] 27 1d [2] 2b 17 [2] 3c 1c [2] 27 52 [2] 1a }

  condition:
    any of them
}