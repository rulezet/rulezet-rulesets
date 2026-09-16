rule TTP_XOR_MULT_DOSStub_c940 {
  strings:
    $key_c940 = { 9d 28 [2] e9 30 [2] ae 32 [2] e9 23 [2] a7 2f [2] ab 25 [2] bc 2e [2] a7 60 [2] 9a }

  condition:
    any of them
}