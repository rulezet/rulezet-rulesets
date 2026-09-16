rule TTP_XOR_MULT_DOSStub_6017 {
  strings:
    $key_6017 = { 34 7f [2] 40 67 [2] 07 65 [2] 40 74 [2] 0e 78 [2] 02 72 [2] 15 79 [2] 0e 37 [2] 33 }

  condition:
    any of them
}