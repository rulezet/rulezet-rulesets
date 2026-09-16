rule TTP_XOR_MULT_DOSStub_7400 {
  strings:
    $key_7400 = { 20 68 [2] 54 70 [2] 13 72 [2] 54 63 [2] 1a 6f [2] 16 65 [2] 01 6e [2] 1a 20 [2] 27 }

  condition:
    any of them
}