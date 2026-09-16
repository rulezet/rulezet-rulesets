rule TTP_XOR_MULT_DOSStub_7300 {
  strings:
    $key_7300 = { 27 68 [2] 53 70 [2] 14 72 [2] 53 63 [2] 1d 6f [2] 11 65 [2] 06 6e [2] 1d 20 [2] 20 }

  condition:
    any of them
}