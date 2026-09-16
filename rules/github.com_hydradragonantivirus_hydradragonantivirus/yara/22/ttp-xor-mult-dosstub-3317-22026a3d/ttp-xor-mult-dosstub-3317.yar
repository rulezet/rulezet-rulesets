rule TTP_XOR_MULT_DOSStub_3317 {
  strings:
    $key_3317 = { 67 7f [2] 13 67 [2] 54 65 [2] 13 74 [2] 5d 78 [2] 51 72 [2] 46 79 [2] 5d 37 [2] 60 }

  condition:
    any of them
}