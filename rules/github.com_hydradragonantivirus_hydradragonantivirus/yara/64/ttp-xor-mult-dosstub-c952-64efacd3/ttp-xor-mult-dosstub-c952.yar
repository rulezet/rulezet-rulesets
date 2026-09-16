rule TTP_XOR_MULT_DOSStub_c952 {
  strings:
    $key_c952 = { 9d 3a [2] e9 22 [2] ae 20 [2] e9 31 [2] a7 3d [2] ab 37 [2] bc 3c [2] a7 72 [2] 9a }

  condition:
    any of them
}