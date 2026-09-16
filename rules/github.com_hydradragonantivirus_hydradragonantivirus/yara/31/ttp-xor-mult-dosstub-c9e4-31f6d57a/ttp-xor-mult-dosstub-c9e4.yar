rule TTP_XOR_MULT_DOSStub_c9e4 {
  strings:
    $key_c9e4 = { 9d 8c [2] e9 94 [2] ae 96 [2] e9 87 [2] a7 8b [2] ab 81 [2] bc 8a [2] a7 c4 [2] 9a }

  condition:
    any of them
}