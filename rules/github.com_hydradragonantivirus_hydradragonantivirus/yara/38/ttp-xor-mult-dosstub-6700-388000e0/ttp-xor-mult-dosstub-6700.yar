rule TTP_XOR_MULT_DOSStub_6700 {
  strings:
    $key_6700 = { 33 68 [2] 47 70 [2] 00 72 [2] 47 63 [2] 09 6f [2] 05 65 [2] 12 6e [2] 09 20 [2] 34 }

  condition:
    any of them
}