rule TTP_XOR_MULT_DOSStub_c972 {
  strings:
    $key_c972 = { 9d 1a [2] e9 02 [2] ae 00 [2] e9 11 [2] a7 1d [2] ab 17 [2] bc 1c [2] a7 52 [2] 9a }

  condition:
    any of them
}