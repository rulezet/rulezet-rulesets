rule TTP_XOR_MULT_DOSStub_5300 {
  strings:
    $key_5300 = { 07 68 [2] 73 70 [2] 34 72 [2] 73 63 [2] 3d 6f [2] 31 65 [2] 26 6e [2] 3d 20 [2] 00 }

  condition:
    any of them
}