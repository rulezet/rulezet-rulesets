rule TTP_XOR_MULT_DOSStub_c93b {
  strings:
    $key_c93b = { 9d 53 [2] e9 4b [2] ae 49 [2] e9 58 [2] a7 54 [2] ab 5e [2] bc 55 [2] a7 1b [2] 9a }

  condition:
    any of them
}