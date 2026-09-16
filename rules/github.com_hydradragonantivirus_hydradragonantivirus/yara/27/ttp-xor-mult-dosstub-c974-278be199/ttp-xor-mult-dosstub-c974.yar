rule TTP_XOR_MULT_DOSStub_c974 {
  strings:
    $key_c974 = { 9d 1c [2] e9 04 [2] ae 06 [2] e9 17 [2] a7 1b [2] ab 11 [2] bc 1a [2] a7 54 [2] 9a }

  condition:
    any of them
}