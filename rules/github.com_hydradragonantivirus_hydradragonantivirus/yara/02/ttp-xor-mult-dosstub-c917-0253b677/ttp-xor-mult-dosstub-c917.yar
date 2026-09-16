rule TTP_XOR_MULT_DOSStub_c917 {
  strings:
    $key_c917 = { 9d 7f [2] e9 67 [2] ae 65 [2] e9 74 [2] a7 78 [2] ab 72 [2] bc 79 [2] a7 37 [2] 9a }

  condition:
    any of them
}