rule TTP_XOR_MULT_DOSStub_c9f1 {
  strings:
    $key_c9f1 = { 9d 99 [2] e9 81 [2] ae 83 [2] e9 92 [2] a7 9e [2] ab 94 [2] bc 9f [2] a7 d1 [2] 9a }

  condition:
    any of them
}