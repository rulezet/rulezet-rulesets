rule TTP_XOR_MULT_DOSStub_5606 {
  strings:
    $key_5606 = { 02 6e [2] 76 76 [2] 31 74 [2] 76 65 [2] 38 69 [2] 34 63 [2] 23 68 [2] 38 26 [2] 05 }

  condition:
    any of them
}