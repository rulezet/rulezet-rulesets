rule TTP_XOR_MULT_DOSStub_c96d {
  strings:
    $key_c96d = { 9d 05 [2] e9 1d [2] ae 1f [2] e9 0e [2] a7 02 [2] ab 08 [2] bc 03 [2] a7 4d [2] 9a }

  condition:
    any of them
}