rule TTP_XOR_MULT_DOSStub_32f5 {
  strings:
    $key_32f5 = { 66 9d [2] 12 85 [2] 55 87 [2] 12 96 [2] 5c 9a [2] 50 90 [2] 47 9b [2] 5c d5 [2] 61 }

  condition:
    any of them
}