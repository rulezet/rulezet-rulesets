rule TTP_XOR_MULT_DOSStub_7617 {
  strings:
    $key_7617 = { 22 7f [2] 56 67 [2] 11 65 [2] 56 74 [2] 18 78 [2] 14 72 [2] 03 79 [2] 18 37 [2] 25 }

  condition:
    any of them
}