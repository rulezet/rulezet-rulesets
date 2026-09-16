rule TTP_XOR_MULT_DOSStub_7360 {
  strings:
    $key_7360 = { 27 08 [2] 53 10 [2] 14 12 [2] 53 03 [2] 1d 0f [2] 11 05 [2] 06 0e [2] 1d 40 [2] 20 }

  condition:
    any of them
}