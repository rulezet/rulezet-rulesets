rule TTP_XOR_MULT_DOSStub_c953 {
  strings:
    $key_c953 = { 9d 3b [2] e9 23 [2] ae 21 [2] e9 30 [2] a7 3c [2] ab 36 [2] bc 3d [2] a7 73 [2] 9a }

  condition:
    any of them
}