rule TTP_XOR_MULT_DOSStub_1400 {
  strings:
    $key_1400 = { 40 68 [2] 34 70 [2] 73 72 [2] 34 63 [2] 7a 6f [2] 76 65 [2] 61 6e [2] 7a 20 [2] 47 }

  condition:
    any of them
}