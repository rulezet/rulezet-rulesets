rule TTP_XOR_MULT_DOSStub_c9ea {
  strings:
    $key_c9ea = { 9d 82 [2] e9 9a [2] ae 98 [2] e9 89 [2] a7 85 [2] ab 8f [2] bc 84 [2] a7 ca [2] 9a }

  condition:
    any of them
}