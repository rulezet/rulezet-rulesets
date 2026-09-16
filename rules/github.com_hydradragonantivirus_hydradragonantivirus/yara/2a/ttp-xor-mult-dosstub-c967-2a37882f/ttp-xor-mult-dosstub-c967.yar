rule TTP_XOR_MULT_DOSStub_c967 {
  strings:
    $key_c967 = { 9d 0f [2] e9 17 [2] ae 15 [2] e9 04 [2] a7 08 [2] ab 02 [2] bc 09 [2] a7 47 [2] 9a }

  condition:
    any of them
}