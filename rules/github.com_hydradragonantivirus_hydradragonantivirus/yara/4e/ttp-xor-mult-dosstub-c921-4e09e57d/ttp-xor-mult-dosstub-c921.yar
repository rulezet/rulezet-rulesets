rule TTP_XOR_MULT_DOSStub_c921 {
  strings:
    $key_c921 = { 9d 49 [2] e9 51 [2] ae 53 [2] e9 42 [2] a7 4e [2] ab 44 [2] bc 4f [2] a7 01 [2] 9a }

  condition:
    any of them
}