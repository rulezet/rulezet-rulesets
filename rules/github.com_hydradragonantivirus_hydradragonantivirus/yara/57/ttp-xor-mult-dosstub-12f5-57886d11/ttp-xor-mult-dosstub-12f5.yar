rule TTP_XOR_MULT_DOSStub_12f5 {
  strings:
    $key_12f5 = { 46 9d [2] 32 85 [2] 75 87 [2] 32 96 [2] 7c 9a [2] 70 90 [2] 67 9b [2] 7c d5 [2] 41 }

  condition:
    any of them
}