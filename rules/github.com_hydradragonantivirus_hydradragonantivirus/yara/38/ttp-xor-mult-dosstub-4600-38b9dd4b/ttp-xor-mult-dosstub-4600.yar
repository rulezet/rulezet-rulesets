rule TTP_XOR_MULT_DOSStub_4600 {
  strings:
    $key_4600 = { 12 68 [2] 66 70 [2] 21 72 [2] 66 63 [2] 28 6f [2] 24 65 [2] 33 6e [2] 28 20 [2] 15 }

  condition:
    any of them
}