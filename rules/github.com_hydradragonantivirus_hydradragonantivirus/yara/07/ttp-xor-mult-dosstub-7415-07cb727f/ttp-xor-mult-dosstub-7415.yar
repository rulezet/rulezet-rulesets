rule TTP_XOR_MULT_DOSStub_7415 {
  strings:
    $key_7415 = { 20 7d [2] 54 65 [2] 13 67 [2] 54 76 [2] 1a 7a [2] 16 70 [2] 01 7b [2] 1a 35 [2] 27 }

  condition:
    any of them
}