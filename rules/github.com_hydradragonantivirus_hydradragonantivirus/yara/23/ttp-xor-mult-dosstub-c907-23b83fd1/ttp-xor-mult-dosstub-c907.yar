rule TTP_XOR_MULT_DOSStub_c907 {
  strings:
    $key_c907 = { 9d 6f [2] e9 77 [2] ae 75 [2] e9 64 [2] a7 68 [2] ab 62 [2] bc 69 [2] a7 27 [2] 9a }

  condition:
    any of them
}