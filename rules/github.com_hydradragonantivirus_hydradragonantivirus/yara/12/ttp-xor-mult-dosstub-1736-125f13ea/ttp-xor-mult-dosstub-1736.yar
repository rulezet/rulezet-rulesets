rule TTP_XOR_MULT_DOSStub_1736 {
  strings:
    $key_1736 = { 43 5e [2] 37 46 [2] 70 44 [2] 37 55 [2] 79 59 [2] 75 53 [2] 62 58 [2] 79 16 [2] 44 }

  condition:
    any of them
}