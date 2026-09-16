rule TTP_XOR_MULT_DOSStub_5165 {
  strings:
    $key_5165 = { 05 0d [2] 71 15 [2] 36 17 [2] 71 06 [2] 3f 0a [2] 33 00 [2] 24 0b [2] 3f 45 [2] 02 }

  condition:
    any of them
}