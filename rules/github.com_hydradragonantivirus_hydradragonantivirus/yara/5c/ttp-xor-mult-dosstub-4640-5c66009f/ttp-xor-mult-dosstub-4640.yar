rule TTP_XOR_MULT_DOSStub_4640 {
  strings:
    $key_4640 = { 12 28 [2] 66 30 [2] 21 32 [2] 66 23 [2] 28 2f [2] 24 25 [2] 33 2e [2] 28 60 [2] 15 }

  condition:
    any of them
}