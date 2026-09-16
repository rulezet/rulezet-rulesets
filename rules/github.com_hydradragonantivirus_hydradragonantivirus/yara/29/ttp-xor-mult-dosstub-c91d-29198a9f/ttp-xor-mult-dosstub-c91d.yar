rule TTP_XOR_MULT_DOSStub_c91d {
  strings:
    $key_c91d = { 9d 75 [2] e9 6d [2] ae 6f [2] e9 7e [2] a7 72 [2] ab 78 [2] bc 73 [2] a7 3d [2] 9a }

  condition:
    any of them
}