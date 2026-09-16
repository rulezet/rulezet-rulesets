rule TTP_XOR_MULT_DOSStub_50f5 {
  strings:
    $key_50f5 = { 04 9d [2] 70 85 [2] 37 87 [2] 70 96 [2] 3e 9a [2] 32 90 [2] 25 9b [2] 3e d5 [2] 03 }

  condition:
    any of them
}