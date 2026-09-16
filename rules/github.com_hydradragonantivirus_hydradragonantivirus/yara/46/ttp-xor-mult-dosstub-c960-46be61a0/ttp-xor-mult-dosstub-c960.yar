rule TTP_XOR_MULT_DOSStub_c960 {
  strings:
    $key_c960 = { 9d 08 [2] e9 10 [2] ae 12 [2] e9 03 [2] a7 0f [2] ab 05 [2] bc 0e [2] a7 40 [2] 9a }

  condition:
    any of them
}