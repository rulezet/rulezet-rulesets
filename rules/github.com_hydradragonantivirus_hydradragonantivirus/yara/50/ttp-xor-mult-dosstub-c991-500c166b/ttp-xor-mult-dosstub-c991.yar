rule TTP_XOR_MULT_DOSStub_c991 {
  strings:
    $key_c991 = { 9d f9 [2] e9 e1 [2] ae e3 [2] e9 f2 [2] a7 fe [2] ab f4 [2] bc ff [2] a7 b1 [2] 9a }

  condition:
    any of them
}