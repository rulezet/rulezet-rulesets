rule TTP_XOR_MULT_DOSStub_c941 {
  strings:
    $key_c941 = { 9d 29 [2] e9 31 [2] ae 33 [2] e9 22 [2] a7 2e [2] ab 24 [2] bc 2f [2] a7 61 [2] 9a }

  condition:
    any of them
}