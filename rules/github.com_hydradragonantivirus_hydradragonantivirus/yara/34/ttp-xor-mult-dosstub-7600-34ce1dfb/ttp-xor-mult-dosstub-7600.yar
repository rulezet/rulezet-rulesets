rule TTP_XOR_MULT_DOSStub_7600 {
  strings:
    $key_7600 = { 22 68 [2] 56 70 [2] 11 72 [2] 56 63 [2] 18 6f [2] 14 65 [2] 03 6e [2] 18 20 [2] 25 }

  condition:
    any of them
}