rule TTP_XOR_MULT_DOSStub_2330 {
  strings:
    $key_2330 = { 77 58 [2] 03 40 [2] 44 42 [2] 03 53 [2] 4d 5f [2] 41 55 [2] 56 5e [2] 4d 10 [2] 70 }

  condition:
    any of them
}