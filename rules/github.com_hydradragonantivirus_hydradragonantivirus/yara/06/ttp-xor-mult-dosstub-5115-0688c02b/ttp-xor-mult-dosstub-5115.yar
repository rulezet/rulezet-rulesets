rule TTP_XOR_MULT_DOSStub_5115 {
  strings:
    $key_5115 = { 05 7d [2] 71 65 [2] 36 67 [2] 71 76 [2] 3f 7a [2] 33 70 [2] 24 7b [2] 3f 35 [2] 02 }

  condition:
    any of them
}