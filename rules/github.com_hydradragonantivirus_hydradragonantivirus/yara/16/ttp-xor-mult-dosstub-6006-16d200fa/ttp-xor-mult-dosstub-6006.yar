rule TTP_XOR_MULT_DOSStub_6006 {
  strings:
    $key_6006 = { 34 6e [2] 40 76 [2] 07 74 [2] 40 65 [2] 0e 69 [2] 02 63 [2] 15 68 [2] 0e 26 [2] 33 }

  condition:
    any of them
}