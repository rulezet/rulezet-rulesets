rule TTP_XOR_MULT_DOSStub_1408 {
  strings:
    $key_1408 = { 40 60 [2] 34 78 [2] 73 7a [2] 34 6b [2] 7a 67 [2] 76 6d [2] 61 66 [2] 7a 28 [2] 47 }

  condition:
    any of them
}