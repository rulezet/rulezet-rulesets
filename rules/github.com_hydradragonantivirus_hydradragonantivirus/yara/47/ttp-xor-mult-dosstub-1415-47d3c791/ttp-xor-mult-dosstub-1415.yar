rule TTP_XOR_MULT_DOSStub_1415 {
  strings:
    $key_1415 = { 40 7d [2] 34 65 [2] 73 67 [2] 34 76 [2] 7a 7a [2] 76 70 [2] 61 7b [2] 7a 35 [2] 47 }

  condition:
    any of them
}