rule TTP_XOR_MULT_DOSStub_6015 {
  strings:
    $key_6015 = { 34 7d [2] 40 65 [2] 07 67 [2] 40 76 [2] 0e 7a [2] 02 70 [2] 15 7b [2] 0e 35 [2] 33 }

  condition:
    any of them
}