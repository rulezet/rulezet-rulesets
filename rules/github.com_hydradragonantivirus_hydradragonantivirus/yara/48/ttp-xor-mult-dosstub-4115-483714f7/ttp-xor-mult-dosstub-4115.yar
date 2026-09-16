rule TTP_XOR_MULT_DOSStub_4115 {
  strings:
    $key_4115 = { 15 7d [2] 61 65 [2] 26 67 [2] 61 76 [2] 2f 7a [2] 23 70 [2] 34 7b [2] 2f 35 [2] 12 }

  condition:
    any of them
}