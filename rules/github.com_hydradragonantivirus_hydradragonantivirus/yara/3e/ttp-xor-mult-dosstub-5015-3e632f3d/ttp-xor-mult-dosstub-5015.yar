rule TTP_XOR_MULT_DOSStub_5015 {
  strings:
    $key_5015 = { 04 7d [2] 70 65 [2] 37 67 [2] 70 76 [2] 3e 7a [2] 32 70 [2] 25 7b [2] 3e 35 [2] 03 }

  condition:
    any of them
}