rule TTP_XOR_MULT_DOSStub_1737 {
  strings:
    $key_1737 = { 43 5f [2] 37 47 [2] 70 45 [2] 37 54 [2] 79 58 [2] 75 52 [2] 62 59 [2] 79 17 [2] 44 }

  condition:
    any of them
}