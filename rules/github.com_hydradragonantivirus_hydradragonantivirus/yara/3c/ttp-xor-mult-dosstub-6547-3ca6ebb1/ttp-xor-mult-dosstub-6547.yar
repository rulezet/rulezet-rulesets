rule TTP_XOR_MULT_DOSStub_6547 {
  strings:
    $key_6547 = { 31 2f [2] 45 37 [2] 02 35 [2] 45 24 [2] 0b 28 [2] 07 22 [2] 10 29 [2] 0b 67 [2] 36 }

  condition:
    any of them
}