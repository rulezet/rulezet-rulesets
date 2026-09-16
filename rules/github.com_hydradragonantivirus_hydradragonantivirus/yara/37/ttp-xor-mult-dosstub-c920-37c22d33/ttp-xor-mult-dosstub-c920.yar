rule TTP_XOR_MULT_DOSStub_c920 {
  strings:
    $key_c920 = { 9d 48 [2] e9 50 [2] ae 52 [2] e9 43 [2] a7 4f [2] ab 45 [2] bc 4e [2] a7 00 [2] 9a }

  condition:
    any of them
}