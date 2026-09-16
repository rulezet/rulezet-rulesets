rule TTP_XOR_MULT_DOSStub_0517 {
  strings:
    $key_0517 = { 51 7f [2] 25 67 [2] 62 65 [2] 25 74 [2] 6b 78 [2] 67 72 [2] 70 79 [2] 6b 37 [2] 56 }

  condition:
    any of them
}