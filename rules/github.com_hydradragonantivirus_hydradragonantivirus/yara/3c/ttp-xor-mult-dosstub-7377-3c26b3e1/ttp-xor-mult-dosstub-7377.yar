rule TTP_XOR_MULT_DOSStub_7377 {
  strings:
    $key_7377 = { 27 1f [2] 53 07 [2] 14 05 [2] 53 14 [2] 1d 18 [2] 11 12 [2] 06 19 [2] 1d 57 [2] 20 }

  condition:
    any of them
}