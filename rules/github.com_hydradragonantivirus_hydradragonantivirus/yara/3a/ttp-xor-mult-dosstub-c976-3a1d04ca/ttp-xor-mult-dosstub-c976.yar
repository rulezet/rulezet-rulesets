rule TTP_XOR_MULT_DOSStub_c976 {
  strings:
    $key_c976 = { 9d 1e [2] e9 06 [2] ae 04 [2] e9 15 [2] a7 19 [2] ab 13 [2] bc 18 [2] a7 56 [2] 9a }

  condition:
    any of them
}