rule TTP_XOR_MULT_DOSStub_3730 {
  strings:
    $key_3730 = { 63 58 [2] 17 40 [2] 50 42 [2] 17 53 [2] 59 5f [2] 55 55 [2] 42 5e [2] 59 10 [2] 64 }

  condition:
    any of them
}