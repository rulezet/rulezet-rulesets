rule TTP_XOR_MULT_DOSStub_c955 {
  strings:
    $key_c955 = { 9d 3d [2] e9 25 [2] ae 27 [2] e9 36 [2] a7 3a [2] ab 30 [2] bc 3b [2] a7 75 [2] 9a }

  condition:
    any of them
}