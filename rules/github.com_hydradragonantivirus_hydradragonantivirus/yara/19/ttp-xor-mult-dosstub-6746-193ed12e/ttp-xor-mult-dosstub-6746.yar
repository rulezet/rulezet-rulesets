rule TTP_XOR_MULT_DOSStub_6746 {
  strings:
    $key_6746 = { 33 2e [2] 47 36 [2] 00 34 [2] 47 25 [2] 09 29 [2] 05 23 [2] 12 28 [2] 09 66 [2] 34 }

  condition:
    any of them
}