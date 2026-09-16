rule TTP_XOR_MULT_DOSStub_3370 {
  strings:
    $key_3370 = { 67 18 [2] 13 00 [2] 54 02 [2] 13 13 [2] 5d 1f [2] 51 15 [2] 46 1e [2] 5d 50 [2] 60 }

  condition:
    any of them
}