rule TTP_XOR_MULT_DOSStub_c978 {
  strings:
    $key_c978 = { 9d 10 [2] e9 08 [2] ae 0a [2] e9 1b [2] a7 17 [2] ab 1d [2] bc 16 [2] a7 58 [2] 9a }

  condition:
    any of them
}