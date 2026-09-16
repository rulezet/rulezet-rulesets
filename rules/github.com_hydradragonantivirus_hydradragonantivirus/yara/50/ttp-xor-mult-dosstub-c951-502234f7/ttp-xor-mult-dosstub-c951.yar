rule TTP_XOR_MULT_DOSStub_c951 {
  strings:
    $key_c951 = { 9d 39 [2] e9 21 [2] ae 23 [2] e9 32 [2] a7 3e [2] ab 34 [2] bc 3f [2] a7 71 [2] 9a }

  condition:
    any of them
}