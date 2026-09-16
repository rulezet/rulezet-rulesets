rule TTP_XOR_MULT_DOSStub_1700 {
  strings:
    $key_1700 = { 43 68 [2] 37 70 [2] 70 72 [2] 37 63 [2] 79 6f [2] 75 65 [2] 62 6e [2] 79 20 [2] 44 }

  condition:
    any of them
}