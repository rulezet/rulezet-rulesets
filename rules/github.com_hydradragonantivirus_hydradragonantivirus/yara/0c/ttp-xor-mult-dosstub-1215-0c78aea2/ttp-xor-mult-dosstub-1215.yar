rule TTP_XOR_MULT_DOSStub_1215 {
  strings:
    $key_1215 = { 46 7d [2] 32 65 [2] 75 67 [2] 32 76 [2] 7c 7a [2] 70 70 [2] 67 7b [2] 7c 35 [2] 41 }

  condition:
    any of them
}