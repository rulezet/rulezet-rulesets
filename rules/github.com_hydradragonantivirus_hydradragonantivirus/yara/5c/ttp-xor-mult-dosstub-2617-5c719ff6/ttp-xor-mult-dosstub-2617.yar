rule TTP_XOR_MULT_DOSStub_2617 {
  strings:
    $key_2617 = { 72 7f [2] 06 67 [2] 41 65 [2] 06 74 [2] 48 78 [2] 44 72 [2] 53 79 [2] 48 37 [2] 75 }

  condition:
    any of them
}