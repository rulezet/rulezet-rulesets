rule TTP_XOR_MULT_DOSStub_7337 {
  strings:
    $key_7337 = { 27 5f [2] 53 47 [2] 14 45 [2] 53 54 [2] 1d 58 [2] 11 52 [2] 06 59 [2] 1d 17 [2] 20 }

  condition:
    any of them
}