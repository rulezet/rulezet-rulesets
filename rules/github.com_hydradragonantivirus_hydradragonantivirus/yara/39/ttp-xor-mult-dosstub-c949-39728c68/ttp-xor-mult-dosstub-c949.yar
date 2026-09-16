rule TTP_XOR_MULT_DOSStub_c949 {
  strings:
    $key_c949 = { 9d 21 [2] e9 39 [2] ae 3b [2] e9 2a [2] a7 26 [2] ab 2c [2] bc 27 [2] a7 69 [2] 9a }

  condition:
    any of them
}