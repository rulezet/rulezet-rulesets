rule TTP_XOR_MULT_DOSStub_6300 {
  strings:
    $key_6300 = { 37 68 [2] 43 70 [2] 04 72 [2] 43 63 [2] 0d 6f [2] 01 65 [2] 16 6e [2] 0d 20 [2] 30 }

  condition:
    any of them
}